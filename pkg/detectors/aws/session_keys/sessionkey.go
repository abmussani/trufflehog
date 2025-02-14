package session_keys

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	logContext "github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/aws"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type scanner struct {
	*detectors.CustomMultiPartCredentialProvider
	verificationClient *http.Client
	skipIDs            map[string]struct{}
}

func New(opts ...func(*scanner)) *scanner {
	scanner := &scanner{
		skipIDs: map[string]struct{}{},
	}
	for _, opt := range opts {
		opt(scanner)
	}

	scanner.CustomMultiPartCredentialProvider = detectors.NewCustomMultiPartCredentialProvider(2048) // ????
	return scanner
}

func WithSkipIDs(skipIDs []string) func(*scanner) {
	return func(s *scanner) {
		ids := map[string]struct{}{}
		for _, id := range skipIDs {
			ids[id] = struct{}{}
		}

		s.skipIDs = ids
	}
}

// Ensure the scanner satisfies the interface at compile time.
var _ interface {
	detectors.Detector
	detectors.CustomResultsCleaner
} = (*scanner)(nil)

var (
	defaultVerificationClient = common.SaneHttpClient()

	// Key types are from this list https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-unique-ids
	idPat      = regexp.MustCompile(`\b((?:ASIA)[A-Z0-9]{16})\b`)
	sessionPat = regexp.MustCompile(`(?:[^A-Za-z0-9+/]|\A)([a-zA-Z0-9+/]{100,}={0,3})(?:[^A-Za-z0-9+/=]|\z)`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s scanner) Keywords() []string {
	return []string{"ASIA"}
}

func (s scanner) getClient() *http.Client {
	if s.verificationClient == nil {
		s.verificationClient = defaultVerificationClient
	}
	return s.verificationClient
}

// FromData will find and optionally verify AWS secrets in a given set of bytes.
func (s scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	logger := logContext.AddLogger(ctx).Logger().WithName("awssessionkey")
	dataStr := string(data)
	dataStr = aws.UrlEncodedReplacer.Replace(dataStr)

	// Filter & deduplicate matches.
	idMatches := make(map[string]struct{})
	for _, matches := range idPat.FindAllStringSubmatch(dataStr, -1) {
		idMatches[matches[1]] = struct{}{}
	}
	secretMatches := make(map[string]struct{})
	for _, matches := range aws.SecretPat.FindAllStringSubmatch(dataStr, -1) {
		secretMatches[matches[1]] = struct{}{}
	}
	sessionMatches := make(map[string]struct{})
	for _, matches := range sessionPat.FindAllStringSubmatch(dataStr, -1) {
		sessionMatches[matches[1]] = struct{}{}
	}

	// Process matches.
	for idMatch := range idMatches {
		if detectors.StringShannonEntropy(idMatch) < aws.RequiredIdEntropy {
			continue
		}
		if s.skipIDs != nil {
			if _, ok := s.skipIDs[idMatch]; ok {
				continue
			}
		}

		for secretMatch := range secretMatches {
			if detectors.StringShannonEntropy(secretMatch) < aws.RequiredSecretEntropy {
				continue
			}

			for sessionMatch := range sessionMatches {
				if detectors.StringShannonEntropy(sessionMatch) < 4.5 {
					continue
				}
				if !checkSessionToken(sessionMatch, secretMatch) {
					continue
				}

				s1 := detectors.Result{
					DetectorType: detectorspb.DetectorType_AWSSessionKey,
					Raw:          []byte(idMatch),
					RawV2:        []byte(fmt.Sprintf("%s:%s:%s", idMatch, secretMatch, sessionMatch)),
					Redacted:     idMatch,
					ExtraData:    make(map[string]string),
				}

				if verify {
					isVerified, extraData, verificationErr := s.verifyMatch(ctx, idMatch, secretMatch, sessionMatch)
					s1.Verified = isVerified
					if extraData != nil {
						s1.ExtraData = extraData
					}
					s1.SetVerificationError(verificationErr, secretMatch)
				}

				if !s1.Verified && aws.FalsePositiveSecretPat.MatchString(secretMatch) {
					// Unverified results that look like hashes are probably not secrets
					continue
				}

				// If we haven't already found an account number for this ID (via API), calculate one.
				if _, ok := s1.ExtraData["account"]; !ok {
					if account, err := aws.GetAccountNumFromID(idMatch); err != nil {
						logger.V(3).Info("Failed to decode account number", "err", err)
					} else {
						s1.ExtraData["account"] = account
					}
				}

				results = append(results, s1)
				// If we've found a verified match with this ID, we don't need to look for any more. So move on to the next ID.
				if s1.Verified {
					delete(sessionMatches, secretMatch)
					delete(sessionMatches, sessionMatch)
					break
				}
			}
		}
	}
	return results, nil
}

func (s scanner) ShouldCleanResultsIrrespectiveOfConfiguration() bool {
	return true
}

const (
	method   = "GET"
	service  = "sts"
	host     = "sts.amazonaws.com"
	region   = "us-east-1"
	endpoint = "https://sts.amazonaws.com"
)

func (s scanner) verifyMatch(ctx context.Context, resIDMatch, resSecretMatch string, resSessionMatch string) (bool, map[string]string, error) {
	// Prep AWS Creds for STS
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithHTTPClient(s.getClient()),
		config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(resIDMatch, resSecretMatch, resSessionMatch),
		),
	)
	if err != nil {
		return false, nil, err
	}
	// Create STS client
	stsClient := sts.NewFromConfig(cfg)

	// Make the GetCallerIdentity API call
	resp, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		if strings.Contains(err.Error(), "StatusCode: 403") || strings.Contains(err.Error(), "InvalidClientTokenId") {
			return false, nil, nil
		}
		return false, nil, fmt.Errorf("request returned unexpected error: %s", err.Error())
	}

	extraData := map[string]string{
		"rotation_guide": "https://howtorotate.com/docs/tutorials/aws/",
		"account":        *resp.Account,
		"user_id":        *resp.UserId,
		"arn":            *resp.Arn,
	}
	return true, extraData, nil
}

func (s scanner) CleanResults(results []detectors.Result) []detectors.Result {
	return aws.CleanResults(results)
}

// Reference: https://nitter.poast.org/TalBeerySec/status/1816449053841838223#m
func checkSessionToken(sessionToken string, secret string) bool {
	if !(strings.Contains(sessionToken, "YXdz") || strings.Contains(sessionToken, "Jb3JpZ2luX2Vj")) ||
		strings.Contains(sessionToken, secret) {
		// Handle error if the sessionToken is not a valid base64 string
		return false
	}
	return true
}

func (s scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_AWSSessionKey
}

func (s scanner) Description() string {
	return "AWS (Amazon Web Services) is a comprehensive cloud computing platform offering a wide range of on-demand services like computing power, storage, databases. API keys for AWS can have varying amount of access to these services depending on the IAM policy attached. AWS Session Tokens are short-lived keys."
}
