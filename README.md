# Path-Traversal-Scanner

This is a bulk scanner for detecting Path Traversal vulnerabilities based on my previous work [CVE-2024-4956 Bulk Scanner](https://github.com/ifconfig-me/CVE-2024-4956-Bulk-Scanner). This scanner scans a list of URLs for path traversal vulnerabilities. It has built-in user agents and rotates between targets to avoid WAF (though this may not always be effective, lol). 

![image](https://github.com/user-attachments/assets/448c2dd0-4258-4830-9b04-c8ae673001a5)

The scanner includes several configurable settings such as batch size, delay, timeout, and retry attempts. Additionally, it checks if the domains in the list have a schema; if not, it automatically prepends "http://" to the raw domain names. 

In the begining of scanning, the scanner displays the following from the default configurations if not provided: 
- Total targets loaded: XXXXX
- Batch size: 150
- Batch delay: 1.5 seconds
- Timeout: 1.8 seconds
- Retry attempts: 1

## Disclaimer

> 1. Bulk Path Traversal Scanner
> 2. Intended only for educational and testing in corporate environments.
> 3. https://twitter.com/nav1n0x/ https://github.com/ifconfig-me takes no responsibility for the code, use at your own risk.
> 4. Do not attack a target you don't have permission to engage with.
> 5. May give a false positive, so confirm the results in the POC file using Burp Suite, etc.

## Features

- Bulk scanning of multiple domains and payloads.
- Randomized user-agent headers to evade detection.
- Configurable batch size, delay, timeout, and retry attempts.
- Writes successful attempts to an output file with detailed information.

## Usage

You can change export file name in the main code in the line number #85 ``` with open("write-poc.txt", "a") as file:```. If not the out[ut will be saved on the directory with file name ```write-poc.txt```. 

![image](https://github.com/ifconfig-me/Path-Traversal-Scanner/assets/25315805/ef326a2d-f1fd-4475-b7f2-506ae44b23da)

### Prerequisites

- Python 3.6 or higher
- `aiohttp` and `colorama` libraries

Install the required libraries using pip:

```
pip install aiohttp colorama
```
## Running the Scanner

> Please use your own payloads.txt file

```
python3 scanner.py -d domains.txt -p payloads.txt [options]
```
### Additional Configurations
```
python3 Bulk-Path-Traversal-Scanner.py [-h] -d DOMAINS -p PAYLOADS [-b BATCH_SIZE] [-bd BATCH_DELAY] [-t TIMEOUT] [-r RETRY_COUNT] [-h HELP] 
```
### Command Line Arguments

    -d, --domains: File containing list of domains (required)
    -p, --payloads: File containing list of payloads (required)
    -b, --batch-size: Number of URLs per batch (default: 150)
    -bd, --batch-delay: Seconds to wait before processing the next batch (default: 1.5)
    -t, --timeout: Timeout for each request in seconds (default: 1.8)
    -r, --retry-count: Number of retry attempts for each request (default: 1)

### Example

```python3 Bulk-Path-Traversal-Scanner.py -d domains.txt -p payloads.txt -b 100 -bd 2 -t 2 -r 3```

### Output
The results will be saved in ```write-poc.txt``` in the following format:
```
Success: http://example.com - Payload: %2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f../etc/passwd - User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
