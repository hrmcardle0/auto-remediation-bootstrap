// Take the config as input, containing:
// target-role-name: Role name to create in each account, this role will be used for autoremediation actions
// permissions: list of permissions to attach to the role
// source-role-arn: role ARN in the source account to be trusted by target account
// actions: list of actions to trigger remediation
// management-role-arn: role ARN in the target accounts to perform the deployments

package setup

import (
	"encoding/json"
	"fmt"
	//"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/eventbridge"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/hrmcardle0/aws-auto-remediation-setup/helpers"
)

var (
	roleSessionName = "CyberSecAutoRemediationSetup"
)

// Assume the management role for intial setup
func AssumeManagementRoleSetup(config *helpers.Config, account string) error {

	managementRoleArn := fmt.Sprintf("arn:aws:iam::%s:role/%s", account, config.ManagementRoleName)
	fmt.Printf("Assuming Management Role: %s\n", managementRoleArn)
	// Create session
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("eu-west-1"),
	})
	if err != nil {
		return err
	}

	// Create STS client
	stsClient := sts.New(sess)

	// Target role
	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(managementRoleArn),
		RoleSessionName: aws.String(roleSessionName),
	}

	// Assume the role
	result, err := stsClient.AssumeRole(input)
	if err != nil {
		return err
	}

	// Get creds
	fmt.Printf("Assumed role successfully: %s - %s\n", managementRoleArn, *result.Credentials.AccessKeyId)
	helpers.Creds.AccessKeyId = *result.Credentials.AccessKeyId
	helpers.Creds.SecretAccessKey = *result.Credentials.SecretAccessKey
	helpers.Creds.SessionToken = *result.Credentials.SessionToken

	return nil

}

// Assume the target role and setup:
// target role
// eventbridge rules
func CreateTargetInfrastructureSetup(config *helpers.Config) error {

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

	// Create the role
	createRoleInput := &iam.CreateRoleInput{
		RoleName:                 aws.String(config.TargetRoleName),
		AssumeRolePolicyDocument: aws.String(helpers.GetAssumeRolePolicy(config.CentralAccount)),
	}

	createRoleOutput, err := iamClient.CreateRole(createRoleInput)
	if err != nil {
		return err
	}

	fmt.Printf("Role Created: %s\n", *createRoleOutput.Role.Arn)

	// Attach permissions
	attachPolicyInput := &iam.AttachRolePolicyInput{
		PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess"),
		RoleName:  aws.String(config.TargetRoleName),
	}

	_, err = iamClient.AttachRolePolicy(attachPolicyInput)
	if err != nil {
		return err
	}

	fmt.Println("Policy attached successfully")

	// Specify the central account event bus as a target
	fmt.Println(config.CentralEventBusArn)
	targetEventBusArn := config.CentralEventBusArn

	assumeRolePolicyEB := `{
	    "Version": "2012-10-17",
	    "Statement": [
	        {
	            "Sid": "",
	            "Effect": "Allow",
	            "Principal": {
	                "Service": "events.amazonaws.com"
	            },
	            "Action": "sts:AssumeRole"
	        }
	    ]
	}`

	// Create event bridge role to assume
	rolePolicyEB := fmt.Sprintf(`{
		"Version": "2012-10-17",
	    "Statement": [
	        {
	            "Action": [
	                "events:PutEvents"
	            ],
	            "Effect": "Allow",
	            "Resource": [
	                "%s"
	            ]
	        }
	    ]
	}`, targetEventBusArn)

	createRoleInputEB := &iam.CreateRoleInput{
		RoleName:                 aws.String(config.EventBridgeRoleName),
		AssumeRolePolicyDocument: aws.String(assumeRolePolicyEB),
	}

	createRoleOutputEB, err := iamClient.CreateRole(createRoleInputEB)
	if err != nil {
		return err
	}

	roleArnEB := *createRoleOutputEB.Role.Arn

	fmt.Println("Role Created: ", roleArnEB)

	// Attach inline policy to the role
	putInlinePolicyInputEB := &iam.PutRolePolicyInput{
		RoleName:       aws.String("CyberSec-AutoRemediation-EventBridge"),
		PolicyName:     aws.String("PutEvents"),
		PolicyDocument: aws.String(rolePolicyEB),
	}

	_, err = iamClient.PutRolePolicy(putInlinePolicyInputEB)
	if err != nil {
		return err
	}

	// Create EventBridge client
	eventBridgeClient := eventbridge.New(sess)

	// Grab actions from config
	serviceToAction := helpers.GetEventBridgeMapping(config)

	for key, value := range serviceToAction {

		ruleName := fmt.Sprintf("AutoRemediation-%s", key)
		fmt.Printf("Adding rule: %s - %s\n", ruleName, value)
		// create event pattern
		eBp := helpers.EventBridgePattern{
			Source: []string{fmt.Sprintf("aws.%s", key)},
			Detail: helpers.Detail{
				EventName: value,
			},
		}

		eventPatternJson, err := json.Marshal(eBp)
		if err != nil {
			return err
		}
		// Create the rule
		putRuleInput := &eventbridge.PutRuleInput{
			Name:         aws.String(ruleName),
			EventPattern: aws.String(string(eventPatternJson)),
			State:        aws.String("ENABLED"),
		}

		putRuleOutput, err := eventBridgeClient.PutRule(putRuleInput)
		if err != nil {
			return err
		}

		fmt.Printf("Rule created successfully: %v\n", *putRuleOutput.RuleArn)
		helpers.EventBridgeRuleNames = append(helpers.EventBridgeRuleNames, ruleName)

		putTargetsInput := &eventbridge.PutTargetsInput{
			Rule: aws.String(ruleName),
			Targets: []*eventbridge.Target{
				{
					Id:      aws.String("CyberSec-EB"),
					Arn:     aws.String(targetEventBusArn),
					RoleArn: aws.String(roleArnEB),
				},
			},
		}

		_, err = eventBridgeClient.PutTargets(putTargetsInput)
		if err != nil {
			return err
		}
	}

	return nil

}
