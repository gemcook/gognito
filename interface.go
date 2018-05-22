package gognito

// UserPoolInterface represents Cognito UserPool Interface
type UserPoolInterface interface {
	DeleteUser(email string) error
}
