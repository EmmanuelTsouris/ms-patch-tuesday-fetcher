# AWS Lambda Setup for Microsoft Patch Tuesday Fetcher

This guide provides instructions on how to deploy and run the `ms-patch-tuesday-fetcher` Python script on AWS Lambda.

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
    Make sure you copy the `ms-patch-tuesday-fetcher.py` file into the `lambda_package` directory.

4. **Create a zip file containing the script and its dependencies**:

    ```bash
    zip -r ms-patch-tuesday-fetcher.zip .
    ```

### Step 2: Deploy to AWS Lambda

1. **Go to the AWS Management Console**.
2. Navigate to **AWS Lambda** and create a new Lambda function.
3. **Choose "Upload a .zip file"** under the **Code** section and upload `ms-patch-tuesday-fetcher.zip`.
4. Set the handler to:

```bash
ms-patch-tuesday-fetcher.lambda_handler
```

   This tells AWS Lambda to use the `lambda_handler` function as the entry point.

### Step 3: Configure AWS Lambda

1. **Configure the runtime** to Python 3.x (3.7, 3.8, or 3.9 are common choices).
2. **Set up the appropriate role** that allows Lambda to log outputs to CloudWatch.
3. (Optional) Adjust the memory, timeout, and other execution settings based on your requirements.

### Step 4: Invoking the Lambda Function

You can invoke the Lambda function via the AWS Management Console or the AWS CLI.

#### Example AWS CLI Invocation

```bash
aws lambda invoke --function-name ms-patch-tuesday-fetcher --payload '{"days": 30, "raw": false}' output.json
```

- **`days`**: Specifies the number of days back to fetch updates (default: 7 days).
- **`raw`**: Set to `true` to include raw API output for debugging (default: `false`).

### Event Structure

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
