package gognito

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
)

// UserIdentityProvider はユーザー認証管理リポジトリです
type UserIdentityProvider struct {
	userPool *UserPool
	idp      *cognitoidentityprovider.CognitoIdentityProvider
}

// NewUserIdentityProvider はユーザー認証管理リポジトリを初期化します
func NewUserIdentityProvider(userPool *UserPool) UserPoolInterface {
	session := GetAWSSession()
	idp := cognitoidentityprovider.New(session)
	u := UserIdentityProvider{
		userPool: userPool,
		idp:      idp,
	}
	return &u
}

// DeleteUser はCognito UserPoolのユーザー削除を行います
//
// ListUsers のAPIドキュメント
// https://docs.aws.amazon.com/sdk-for-go/api/service/cognitoidentityprovider/#CognitoIdentityProvider.ListUsers
//
// AdminDeleteUser のAPIドキュメント
// https://docs.aws.amazon.com/sdk-for-go/api/service/cognitoidentityprovider/#CognitoIdentityProvider.AdminDeleteUser
func (u *UserIdentityProvider) DeleteUser(email string) error {

	wantAttrs := make([]*string, 0, 10)
	subAttr := "sub"
	wantAttrs = append(wantAttrs, &subAttr)
	filter := fmt.Sprintf("email = \"%s\"", email)

	listInput := &cognitoidentityprovider.ListUsersInput{
		UserPoolId:      &u.userPool.PoolID,
		AttributesToGet: wantAttrs,
		Filter:          &filter,
	}

	// limit は60以下にセット必須
	listInput.SetLimit(60)

	listOutput, err := u.idp.ListUsers(listInput)
	if err != nil {
		return err
	}

	if len(listOutput.Users) == 0 {
		return fmt.Errorf("cognito user not found for email = %v", email)
	}

	errList := make([]string, 0, len(listOutput.Users))

	for _, user := range listOutput.Users {
		if user.Username == nil {
			continue
		}
		deleteInput := &cognitoidentityprovider.AdminDeleteUserInput{
			UserPoolId: &u.userPool.PoolID,
			Username:   user.Username,
		}
		_, err := u.idp.AdminDeleteUser(deleteInput)
		if err != nil {
			errList = append(errList, err.Error())
		}
	}

	if len(errList) > 0 {
		return errors.New(strings.Join(errList, ", "))
	}

	return nil
}
