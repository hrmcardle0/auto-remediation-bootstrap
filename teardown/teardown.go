// The teardown package represents all required actions needed to teardown the environment

package teardown

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/eventbridge"
	"github.com/aws/aws-sdk-go/service/iam"
	//"github.com/aws/aws-sdk-go/service/sts"
	"github.com/hrmcardle0/aws-auto-remediation-setup/helpers"
)

func Teardown(config *helpers.Config) error {

	fmt.Printf("Tearing down infrastructure using %s\n", helpers.Creds.AccessKeyId)

	// Setup session
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String("eu-west-1"),
		Credentials: credentials.NewStaticCredentials(helpers.Creds.AccessKeyId, helpers.Creds.SecretAccessKey, helpers.Creds.SessionToken),
	})
	if err != nil {
		return err
	}

	// Create IAM client
	iamClient := iam.New(sess)

	// Create EventBridge client
	eventBridgeClient := eventbridge.New(sess)

	// Delete target role
	err = helpers.DeleteRole(iamClient, config.TargetRoleName, "managed")
	if err != nil {
		return err
	}

	// Delete eventbridge role
	err = helpers.DeleteRole(iamClient, config.EventBridgeRoleName, "inline")
	if err != nil {
		return err
	}

	// Delete eventbridge RULEs
	serviceToAction := helpers.GetEventBridgeMapping(config)
	for key, _ := range serviceToAction {
		ruleName := fmt.Sprintf("AutoRemediation-%s", key)
		err = helpers.DeleteEventBridgeRule(eventBridgeClient, ruleName)
		if err != nil {
			return err
		}
	}
	return nil
}
