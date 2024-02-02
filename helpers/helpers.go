package helpers

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/eventbridge"
	"github.com/aws/aws-sdk-go/service/iam"
	"strings"
	//"strings"
)

func GetAssumeRolePolicy(accountID string) string {
	// AssumeRole policy document allowing the specified AWS account to assume the role
	return fmt.Sprintf(`{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Effect": "Allow",
				"Principal": {
					"AWS": "arn:aws:iam::%s:root"
				},
				"Action": "sts:AssumeRole"
			}
		]
	}`, accountID)
}

func GetEventBridgeMapping(config *Config) map[string][]string {
	serviceToAction := map[string][]string{}
	for _, permission := range config.Actions {
		parts := strings.Split(permission, ":")

		if len(parts) == 2 {
			service := parts[0]
			action := parts[1]

			serviceToAction[service] = append(serviceToAction[service], action)
		} else {
			fmt.Printf("Invalid format for permissions")
		}
	}

	return serviceToAction
}

func DeleteRole(iamClient *iam.IAM, roleName string, pType string) error {

	fmt.Printf("Deleting Role: %s\n", roleName)

	if pType == "managed" {
		// Detach policies
		listAttachedPoliciesInput := &iam.ListAttachedRolePoliciesInput{
			RoleName: aws.String(roleName),
		}

		listAttachedPoliciesOutput, err := iamClient.ListAttachedRolePolicies(listAttachedPoliciesInput)
		if err != nil {
			return err
		}

		for _, policy := range listAttachedPoliciesOutput.AttachedPolicies {
			detachPolicyInput := &iam.DetachRolePolicyInput{
				RoleName:  aws.String(roleName),
				PolicyArn: policy.PolicyArn,
			}

			_, err := iamClient.DetachRolePolicy(detachPolicyInput)
			if err != nil {
				return nil
			}

			fmt.Printf("Policy %s detached from role.\n", *policy.PolicyName)
		}
	} else {
		deleteRolePolicyInput := &iam.DeleteRolePolicyInput{
			RoleName:   aws.String(roleName),
			PolicyName: aws.String("PutEvents"),
		}

		_, err := iamClient.DeleteRolePolicy(deleteRolePolicyInput)
		if err != nil {
			return err
		}

		fmt.Println("PutEvents inline policy detached from fole.")
	}

	// Delete the role
	deleteRoleInput := &iam.DeleteRoleInput{
		RoleName: aws.String(roleName),
	}

	_, err := iamClient.DeleteRole(deleteRoleInput)
	if err != nil {
		return err
	}

	fmt.Printf("Role Succesfully Deleted: %s\n", roleName)
	return nil
}

func DeleteEventBridgeRule(client *eventbridge.EventBridge, ruleName string) error {
	fmt.Printf("Deleting EventBridge Rule: %s\n", ruleName)

	deleteRuleInput := &eventbridge.DeleteRuleInput{
		Name: aws.String(ruleName),
	}

	// remove targets
	listTargetsByRuleInput := &eventbridge.ListTargetsByRuleInput{
		Rule: aws.String(ruleName),
	}

	listTargetsByRuleOutput, err := client.ListTargetsByRule(listTargetsByRuleInput)
	if err != nil {
		return err
	}

	var targetIds []*string
	for _, target := range listTargetsByRuleOutput.Targets {
		targetIds = append(targetIds, target.Id)
	}

	removeTargetsInput := &eventbridge.RemoveTargetsInput{
		Ids:  targetIds,
		Rule: aws.String(ruleName),
	}

	_, err = client.RemoveTargets(removeTargetsInput)
	if err != nil {
		return err
	}
	_, err = client.DeleteRule(deleteRuleInput)
	if err != nil {
		return err
	}

	fmt.Printf("EventBridge Rule Deleted: %s\n", ruleName)
	return nil
}
