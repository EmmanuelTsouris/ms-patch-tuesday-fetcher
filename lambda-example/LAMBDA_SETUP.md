# AWS Lambda Setup for Microsoft Patch Tuesday Fetcher

This guide provides instructions on how to deploy and run the `ms-patch-tuesday-fetcher-lambda.py` Python script on AWS Lambda.

## Steps to Set Up the Script in AWS Lambda

### Step 1: Package the Script and Dependencies

AWS Lambda requires dependencies to be packaged with your script in a `.zip` file.

1. **Create a directory for the Lambda package**:

    ```bash
    mkdir lambda_package
    cd lambda_package
    ```

2. **Install the necessary Python dependencies into the directory**:

    ```bash
    pip install requests beautifulsoup4 -t .
    ```

3. **Copy the Python script into the same directory**:
    Ensure that the file `ms-patch-tuesday-fetcher-lambda.py` is inside the `lambda_package` directory.

4. **Create a zip file containing the script and its dependencies**:

    ```bash
    zip -r ms-patch-tuesday-fetcher-lambda.zip .
    ```

### Step 2: Upload the ZIP File to an S3 Bucket

1. Upload the `ms-patch-tuesday-fetcher-lambda.zip` file to an S3 bucket in your AWS account.

### Step 3: Deploy Using CloudFormation

You can use a CloudFormation template to automate the deployment of the Lambda function. The provided `lambda-cfn.yml` file sets up the Lambda function and the necessary IAM role.

#### CloudFormation Template

1. Replace the following placeholders in the `lambda-cfn.yml` template:
   - `your-s3-bucket-name`: The name of your S3 bucket.
   - `your-lambda-zip-file.zip`: The name of the uploaded zip file (`ms-patch-tuesday-fetcher-lambda.zip`).

2. Deploy the CloudFormation stack using the AWS CLI:

    ```bash
    aws cloudformation create-stack --stack-name ms-patch-tuesday-fetcher --template-body file://lambda-cfn.yml --capabilities CAPABILITY_NAMED_IAM
    ```

This will create the necessary resources, including the Lambda function and IAM role.

### Step 4: Invoking the Lambda Function

You can invoke the Lambda function via the AWS Management Console or the AWS CLI.

#### Example AWS CLI Invocation

```bash
aws lambda invoke --function-name ms-patch-tuesday-fetcher-lambda --payload '{"days": 30, "raw": false}' output.json
```

- **`days`**: Specifies the number of days back to fetch updates (default: 7 days).
- **`raw`**: Set to `true` to include raw API output for debugging (default: `false`).

#### Event Structure

The `lambda_handler` function accepts a JSON event with the following structure:

- **`days`** (integer): Number of days back to fetch updates. Defaults to 7 days if not provided.
- **`raw`** (boolean): Set to `true` to display the raw API output.

Example event payload:

```json
{
  "days": 30,
  "raw": true
}
```

### Step 5: Testing the Lambda Function

You can test the function using a custom test event. Create a `test-event.json` file with the following content:

```json
{
  "days": 7,
  "raw": false
}
```

In the AWS Management Console:

1. Go to the Lambda function.
2. Click the **Test** button.
3. Select **Configure test event**.
4. Create a new test event and paste the contents of `test-event.json`.
5. Save and run the test.

### Example Output

If the Lambda function is invoked successfully, you should see output similar to the following in the AWS Lambda Console or in your output file (if using CLI):

```json
{
    "statusCode": 200,
    "body": [
        {
            "title": "September 2024 Security Updates",
            "release_date": "2024-09-10T07:00:00Z",
            "kb_articles": [
                "KB5002624 (Applies to: SharePoint Enterprise Server 2016)",
                "KB5002639 (Applies to: SharePoint Server 2019)"
            ]
        }
    ]
}
```
