# Auto-Remediation Bootstrap

This Go program leverages the AWS Go SDK to bootstrap EventBridge rules and roles in targeted accounts, allowing you to capture specific AWS API calls and forward them to a centralized event bus.
Typically this is used for securty purposes, allowing a centralized security account to be alerted upon various AWS actions that they deem actionable. For example, somebody creating NAT gateway 
when your infrastructure uses an on-prem proxy, or when a user creates a new SAML provider. Maybe you want to capture all s3 CreateBucket events to check that encryption is enabled

## Configuration

A YAML config file is used to specify details about the what is being deployed. The following are configurable:

- target_role_name - the target role to be created. This will be assumable by your central account in order to perform remediation actions
- central_account - the AccountId of the central AWS account, typically the one that does this deployments
- actions - list(actions), a list of actions in the standard IAM format service:action, for example, s3:CreateBucket
- eventbridge_role_name - the name of the EventBridge role to be created, this is required so your rules can use this role to send events back to your central account
- central_event_bus_arn - the arn of the event bus in your central account

It's expected the following are already stood up in your central account:

- Cross account event bus with a policy allowing all targeted accounts to push events
- Lambda functions to handle incoming events

## Compilation

Compiled via go 1.20.12 

```
go build .

```

## Usage

A flag triggers whether the deployment is a creation or destruction event.

creation:

```
./[executable] --destroy false
```

destruction:

```
./[executable] -- destroy true
```