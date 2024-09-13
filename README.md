# Microsoft Patch Tuesday Fetcher

This Python script fetches the latest Microsoft Patch Tuesday updates from Microsoft's Security Update API. It extracts the KB articles, products affected, and CVE information, and displays them in a readable format.

## Features

- Fetch Microsoft Patch Tuesday updates within a specified number of days.
- Extract and display KB articles and CVE numbers.
- Option to show raw API output for debugging purposes.

## Prerequisites

- [Miniconda](https://docs.conda.io/en/latest/miniconda.html) (or [Anaconda](https://www.anaconda.com/products/distribution))
- Python 3.x
- The following Python packages:
  - `requests`
  - `beautifulsoup4`

For instructions on deploying this script to AWS Lambda, see the [Lambda Setup Guide](./lambda-example/LAMBDA_SETUP.md).

## Setup

### Step 1: Create a Conda environment

You can create and activate a Conda environment for this project by running:

```bash
conda create --name ms-patch-fetcher python=3
conda activate ms-patch-fetcher
```

### Step 2: Install Dependencies

Once the environment is activated, install the necessary dependencies:

```bash
conda install requests beautifulsoup4
```

Alternatively, you can use `pip`:

```bash
pip install requests beautifulsoup4
```

### Step 3: Clone the Repository

Clone this repository to your local machine:

```bash
git clone https://github.com/EmmanuelTsouris/ms-patch-tuesday-fetcher.git
cd ms-patch-tuesday-fetcher
```

### Step 4: Run the Script

You can run the script to fetch the latest Patch Tuesday updates for a default of the last 7 days:

```bash
python ms-patch-tuesday-fetcher.py
```

#### Fetching Updates from the Last X Days

To fetch updates from the last X number of days, use the `--days` argument:

```bash
python ms-patch-tuesday-fetcher.py --days 30
```

This will fetch updates from the last 30 days.

#### Show Raw API Output for Debugging

To see the raw API output for debugging purposes, use the `--raw` flag:

```bash
python ms-patch-tuesday-fetcher.py --raw
```

You can also combine the `--raw` and `--days` arguments, for example:

```bash
python ms-patch-tuesday-fetcher.py --days 30 --raw
```

## How It Works

- The script fetches Microsoft Patch Tuesday updates from the [Microsoft Security Update Guide API](https://api.msrc.microsoft.com/).
- It extracts KB articles, products affected, and CVE numbers from the returned data and prints them to the console.
- The script can also print the raw API response for debugging using the `--raw` flag.

## Example Output

```bash
Found 1 updates from the last 7 days.
- Title: September 2024 Security Updates, Released on: 2024-09-10T07:00:00Z
  KB Articles:
  - KB5002624 (Applies to: SharePoint Enterprise Server 2016)
  - KB5002639 (Applies to: SharePoint Server 2019)
  - KB5002640 (Applies to: SharePoint Server Subscription Edition)
  - KB5042881 (Applies to: Windows 11, version 21H2)
```

## Contributing

If you'd like to contribute to this project, feel free to fork the repository, make your changes, and submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.
