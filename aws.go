package gognito

import (
	"github.com/aws/aws-sdk-go/aws/session"
)

var awsSession *session.Session

// GetAWSSession はAWSセッションを取得します
// https://docs.aws.amazon.com/sdk-for-go/api/aws/session/
func GetAWSSession() *session.Session {
	if awsSession == nil {
		awsSession = session.Must(session.NewSession())
	}
	return awsSession
}
