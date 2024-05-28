# Bulk Path Traversal Scanner
# Intended only for educational and testing in corporate environments.
# https://twitter.com/nav1n0x/ https://github.com/ifconfig-me takes no responsibility for the code, use at your own risk.
# Do not attack a target you don't have permission to engage with.
# May give a flase positive, so confirm the results in the poc file, using Burp Suite etc. 

import asyncio
import aiohttp
import argparse
import random
from colorama import init, Fore, Style

# Default values
DEFAULT_BATCH_SIZE = 150
DEFAULT_BATCH_DELAY = 1.5
DEFAULT_TIMEOUT = 1.8
DEFAULT_RETRY_COUNT = 1
RESPONSE_SIZE_LIMIT = 1024 * 10  # 10 KB

init(autoreset=True)

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:86.0) Gecko/20100101 Firefox/86.0"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246"
    "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/601.3.9 (KHTML, like Gecko) Version/9.0.2 Safari/601.3.9"
]

headers = {
    "Upgrade-Insecure-Requests": "1",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "close"
}

successful_attempts = 0
failed_attempts = 0
timeout_attempts = 0

ascii_art = """
                   ____        
  ____ _____ ___  _/_   | ____  
 /    \\\\__  \\\\  \\/ /|   |/    \\ 
|   |  \\/ __ \\\\   / |   |   |  \\
|___|  (____  /\\_/  |___|___|  /
     \\/     \\/         v.0.2 \\/
     
# Bulk Path Traversal Scanner
# Intended only for educational and testing in corporate environments.
# https://twitter.com/nav1n0x/ https://github.com/ifconfig-me takes no responsibility for the code, use at your own risk.
# Do not attack a target you don't have permission to engage with.
# May give a flase positive, so confirm the results in the poc file, using Burp Suite etc. 

usage: scanner.py [-h] -d DOMAINS -p PAYLOADS [-b BATCH_SIZE] [-bd BATCH_DELAY] [-t TIMEOUT] [-r RETRY_COUNT] [-h HELP] 

"""

print(Fore.CYAN + ascii_art + Style.RESET_ALL)

def is_valid_passwd(content):
    
    if len(content) > RESPONSE_SIZE_LIMIT:
        return False
    lines = content.split('\n')
    valid_lines = [line for line in lines if ':' in line and line.count(':') == 6]
    if len(valid_lines) >= 10:  
        return True
    return False

async def send_request(session, domain, payload, index, total, timeout, retry_count):
    global successful_attempts, failed_attempts, timeout_attempts
    url = f"{domain}/{payload}"
    user_agent = random.choice(user_agents)
    headers["User-Agent"] = user_agent
    delay = random.uniform(0.5, 1.5)  
    
    for attempt in range(retry_count):
        try:
            async with session.get(url, headers=headers, ssl=False, timeout=timeout) as response:
                content = await response.text()
                if is_valid_passwd(content):
                    with open("write-poc.txt", "a") as file:
                        file.write(f"Success: {domain} - Payload: {payload} - User-Agent: {user_agent}\n")
                    successful_attempts += 1
                else:
                    failed_attempts += 1
                break
        except asyncio.TimeoutError:
            timeout_attempts += 1
        except Exception as e:
            failed_attempts += 1

    await asyncio.sleep(delay)  

async def process_batch(session, tasks, batch_delay):
    await asyncio.gather(*tasks)
    print(f"{Fore.BLUE}Batch completed. Waiting for {batch_delay} seconds before the next batch.")
    await asyncio.sleep(batch_delay)

async def main(domains_file, payloads_file, batch_size, batch_delay, timeout, retry_count):
    global successful_attempts, failed_attempts, timeout_attempts
    async with aiohttp.ClientSession() as session:
        with open(domains_file, "r") as file:
            domains = file.read().splitlines()
        
        with open(payloads_file, "r") as file:
            payloads = file.read().splitlines()

        total_targets = len(domains) * len(payloads)
        print(f"{Fore.BLUE}Total targets to scan: {total_targets}")
        print(f"{Fore.BLUE}Batch size: {batch_size}, Batch delay: {batch_delay} seconds, Timeout: {timeout} seconds, Retry attempts: {retry_count}")

        tasks = []
        index = 0
        for domain in domains:
            domain = domain.strip()
            if not domain.startswith('http://') and not domain.startswith('https://'):
                domain = 'http://' + domain
            for payload in payloads:
                task = send_request(session, domain, payload, index, total_targets, timeout, retry_count)
                tasks.append(task)
                index += 1

                if len(tasks) >= batch_size:
                    await process_batch(session, tasks, batch_delay)
                    tasks = []
                    print(f"Scanning {index}/{total_targets} URLs - {Fore.GREEN}Success: {successful_attempts}{Fore.RESET}, {Fore.RED}Fail: {failed_attempts}{Fore.RESET}, {Fore.YELLOW}Timeout: {timeout_attempts}{Fore.RESET}")

        if tasks:  
            await process_batch(session, tasks, batch_delay)
            print(f"Scanning {index}/{total_targets} URLs - {Fore.GREEN}Success: {successful_attempts}{Fore.RESET}, {Fore.RED}Fail: {failed_attempts}{Fore.RESET}, {Fore.YELLOW}Timeout: {timeout_attempts}{Fore.RESET}")
        
        print(f"\n{Fore.BLUE}Task execution completed.")
        print(f"{Fore.GREEN}Successful attempts: {successful_attempts}/{total_targets}")
        print(f"{Fore.RED}Failed attempts: {failed_attempts}/{total_targets}")
        print(f"{Fore.YELLOW}Timeout attempts: {timeout_attempts}/{total_targets}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan domains with multiple payloads")
    parser.add_argument("-d", "--domains", required=True, help="File containing list of domains")
    parser.add_argument("-p", "--payloads", required=True, help="File containing list of payloads")
    parser.add_argument("-b", "--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help="Number of URLs per batch")
    parser.add_argument("-bd", "--batch-delay", type=float, default=DEFAULT_BATCH_DELAY, help="Seconds to wait before processing the next batch")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT, help="Timeout for each request in seconds")
    parser.add_argument("-r", "--retry-count", type=int, default=DEFAULT_RETRY_COUNT, help="Number of retry attempts for each request")
    args = parser.parse_args()
    
    asyncio.run(main(args.domains, args.payloads, args.batch_size, args.batch_delay, args.timeout, args.retry_count))
