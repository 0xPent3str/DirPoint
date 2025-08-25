import asyncio
from playwright.async_api import async_playwright
import re
import argparse
from urllib.parse import urljoin
import signal
import sys
import logging

# Configure logging to suppress low-level Playwright errors that
# often appear during graceful shutdowns (like "pipe closed by peer").
logging.getLogger("playwright").setLevel(logging.CRITICAL)
logging.getLogger("asyncio").setLevel(logging.CRITICAL)

# --- ASCII Art Banner ---
BANNER = r"""
*******************************************************************************************
*	       ________  .__                     .__        __                            *
*	       \______ \ |__|_____  _____   ____ |__| _____/  |_                          *
*	        |    |  \|  \_  __ |\____ \ /  _ \|  |/    \   __\                        *  
*	        |    `   \  ||  | ||  |_> >  <_> )  |   |  \  |                           *   
*	       /_______  /__||__| ||   __/ \____/|__|___|  /__|                           *
*	               \/          |__|                  \/                               *
*                                                                                         *
*  Dirpoint 1.0.0                                                                         *
*  Coded by 0xPent3str                                                                           *
*  0xPent3str Penetration Tester                                                                 *
*                                                                                         *
*******************************************************************************************

[!] Legal disclaimer: Usage of Dirpoint for attacking targets without prior mutual consent is illegal.
It is the end user's responsibility to obey all applicable local, state and federal laws.
Developers assume no liability and are not responsible for any misuse or damage caused by this program.
"""
# --- End ASCII Art Banner ---

# List of common TLDs to look for. This can be extended.
COMMON_TLDS = [
    ".com", ".org", ".net", ".io", ".co", ".uk", ".de", ".fr", ".cn", ".jp",
    ".info", ".biz", ".xyz", ".me", ".tv", ".app", ".dev", ".online", ".store",
    ".site", ".club", ".mobi", ".icu", ".top", ".wiki", ".gov", ".edu", ".mil",
    ".int", ".arpa", ".aero", ".coop", ".museum", ".name", ".pro", ".travel",
    ".tech", ".space", ".link", ".digital", ".media", ".solutions", ".cloud",
    ".design", ".email", ".world", ".group", ".live", ".guru", ".expert", ".systems",
    ".agency", ".global", ".blog", ".shop", ".news", ".data", ".build", ".care",
    ".center", ".company", ".domains", ".events", ".finance", ".graphics", ".house",
    ".investments", ".legal", ".life", ".market", ".network", ".photography",
    ".pictures", ".properties", ".rentals", ".reviews", ".services", ".social",
    ".software", ".studio", ".tools", ".training", ".ventures", ".vodka", ".website",
    ".zone", ".ai", ".ru", ".br", ".in", ".ca", ".au", ".pk", ".sg", ".kr", ".se",
    ".nl", ".ch", ".at", ".be", ".dk", ".fi", ".gr", ".ie", ".il", ".nz", ".pt",
    ".sa", ".es", ".th", ".tr", ".ua", ".vn", ".za", ".ph", ".my", ".mx", ".no",
    ".pl", ".ro", ".by", ".kz", ".az", ".ge", # 
    # More specific or new TLDs can be added as needed
]
# Create a regex pattern to find any of these TLDs within a URL
TLD_PATTERN = r'\.(?:' + '|'.join([tld.lstrip('.') for tld in COMMON_TLDS]) + r')(?![a-zA-Z0-9-])'


def normalize_url(base_url, link):
    """Normalize a relative or malformed URL to an absolute URL."""
    if link.startswith("//"):
        return "https:" + link
    elif link.startswith("/"):
        return urljoin(base_url, link)
    elif link.startswith("http"):
        return link
    return urljoin(base_url, link)


async def extract_all_links_from_dom(page, base_url, filter_word, verbose):
    """
    Looks for all links within HTML DOM attributes.
    """
    links = set()
    elements = await page.query_selector_all("*")
    for el in elements:
        try:
            attrs = await page.evaluate("""
                (el) => {
                    let obj = {};
                    for (let attr of el.attributes) {
                        obj[attr.name] = attr.value;
                    }
                    return obj;
                }
            """, el)

            for val in attrs.values():
                if not val:
                    continue
                # Regex to find URLs that start with http(s)://, //, or /
                matches = re.findall(r'(https?://[^\s"\'<>]+|//[^\s"\'<>]+|/[^\s"\'<>]+)', val)
                for raw_url in matches:
                    full_url = normalize_url(base_url, raw_url)
                    if not filter_word or filter_word.lower() in full_url.lower():
                        if full_url not in links:
                            if verbose:
                                print(f"[DOM] {full_url}")
                            links.add(full_url)
        except Exception as e:
            if verbose:
                print(f"[Warning-Error-DOM]: {e}")
            continue
    return links


async def main():
    # Print the ASCII art banner at the very beginning of the script execution.
    print(BANNER)

    parser = argparse.ArgumentParser(description="Search for all files and find links within them, including TLD.")
    parser.add_argument("--url", required=True, help="Site URL")
    parser.add_argument("--filter", help="Link Filter (Optional)")
    parser.add_argument("--output", default="found_links.txt", help="Results file (Optional)")
    parser.add_argument("--depth", type=int, default=2, help="Maximum recursion depth (Optional)")
    parser.add_argument("--verbose", action="store_true", help="Detailed logs")
    args = parser.parse_args()

    url = args.url
    filter_word = args.filter
    output_file = args.output
    max_depth = args.depth
    verbose = args.verbose

    all_scannable_urls = set()
    found_links = set()
    visited_scannable_urls = set()

    # --- Load existing links from file at the start ---
    existing_links_in_file = set()
    try:
        with open(output_file, "r", encoding="utf-8") as f:
            for line in f:
                existing_links_in_file.add(line.strip())
        if verbose:
            print(f"{len(existing_links_in_file)} links found in the existing file: {output_file}")
    except FileNotFoundError:
        if verbose:
            print(f"The output file {output_file} was not found, a new one will be created")
    except Exception as e:
        print(f"└── [Error-Reading-existing-Link] Error reading existing links: {e}")
    
    found_links.update(existing_links_in_file)
    # --- End load existing links ---

    browser = None
    context = None
    page = None
    
    # Flag to indicate if shutdown is initiated
    shutdown_initiated = False

    async def graceful_shutdown():
        """
        Handles graceful shutdown, closing the browser and saving results.
        """
        nonlocal browser, shutdown_initiated
        if shutdown_initiated:
            return
        shutdown_initiated = True

        print("\n--------- [Stop-Process] ---------")
        if browser:
            try:
                await browser.close()
                if verbose:
                    print("└──[Browser-Success-Close]")
            except Exception as e:
                print(f"└── [Error-Browser]: {e}")
        
        try:
            new_links_to_write = sorted(list(found_links - existing_links_in_file))
            if new_links_to_write:
                with open(output_file, "a", encoding="utf-8") as f:
                    for link in new_links_to_write:
                        f.write(link + "\n")
                print(f"\n [Link-New-Unique-Add] {len(new_links_to_write)} ")
            else:
                print("\n[Link-Not-Add]")
            #print(f"Final number of unique links: {len(found_links)}")
            print(f"Save/Update in FIle: {output_file}")
        except Exception as e:
            print(f"[Error-Files-Write]: {e}")
        
        raise asyncio.CancelledError("Graceful shutdown initiated.")

    # Register signal handler for Ctrl+C (SIGINT).
    signal.signal(signal.SIGINT, lambda s, f: asyncio.create_task(graceful_shutdown()))

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
                locale="en-US",
                viewport={"width": 1280, "height": 800},
                java_script_enabled=True
            )

            page = await context.new_page()

            def handle_response(response):
                """
                Monitors network responses to identify scannable files (e.g., JS, CSS, JSON, TXT).
                """
                content_type = response.headers.get("content-type", "").lower()
                is_text_based = any(
                    text_type in content_type for text_type in [
                        "text/", "application/json", "application/javascript",
                        "application/xml", "application/x-www-form-urlencoded",
                        "image/svg+xml",
                    ]
                )      
                
                path = response.url.lower().split('?')[0].split('#')[0]
                is_common_text_file_extension = any(
                    path.endswith(ext) for ext in [
                        ".js", ".css", ".json", ".txt", ".xml", ".html", ".svg",
                        ".ts", ".jsx", ".tsx", ".vue", ".php", ".asp", ".aspx", ".jsp",
                        ".py", ".rb", ".go", ".c", ".cpp", ".java", ".sh", ".ps1", ".md",
                    ]
                )

                if response.ok and (is_text_based or is_common_text_file_extension):
                    all_scannable_urls.add(response.url)
                    if verbose:
                        print(f" [Found] : {response.url}")

            page.on("response", handle_response)

            print(f"----- Scanning URL: {url} -----")
            try:
                await page.goto(url, timeout=120000, wait_until="domcontentloaded")
                #print("Page loaded successfully.")
            except Exception as e:
                print(f"└── [Error-Page-Redirect]: {e}")
                return

            await asyncio.sleep(1.5)
            await page.mouse.move(200, 300)
            await page.mouse.move(400, 500)
            await asyncio.sleep(1)

            # Scroll down to trigger lazy loading.
            await page.evaluate("""
                () => {
                    let y = 0;
                    let interval = setInterval(() => {
                        window.scrollBy(0, 120);
                        y += 120;
                        if (y >= document.body.scrollHeight) clearInterval(interval);
                    }, 300);
                }
            """)
            await asyncio.sleep(4)

            # Search for links within HTML DOM attributes.
            print("\n --------- Found HTML DOM All attribute --------- ")
            try:
                dom_links = await extract_all_links_from_dom(page, url, filter_word, verbose)
                found_links.update(dom_links)
            except Exception as e:
                print(f"[Warning-DOM-Not-Found-Link]: {e}")

            # Extract script src, link href, and other potential URL-containing tags.
            elements_with_urls = await page.eval_on_selector_all(
                "script[src], link[href], a[href], img[src], form[action], iframe[src], [data-url], [data-src], [data-href]",
                "nodes => nodes.map(n => n.src || n.href || n.action || n.dataset.url || n.dataset.src || n.dataset.href)"
            )
            if verbose:
                print(f"\n--------- Links found in HTML tags: {len(elements_with_urls)} ---------")
            for element_url in elements_with_urls:
                if element_url:
                    full_element_url = normalize_url(url, element_url)
                    if not filter_word or filter_word.lower() in full_element_url.lower():
                        if full_element_url not in found_links:
                            if verbose:
                                print(f" + {full_element_url}")
                            found_links.add(full_element_url)
                    
                    path = full_element_url.lower().split('?')[0].split('#')[0]
                    if any(path.endswith(ext) for ext in [
                        ".js", ".css", ".json", ".txt", ".xml", ".html", ".svg",
                        ".ts", ".jsx", ".tsx", ".vue", ".php", ".asp", ".aspx", ".jsp",
                        ".py", ".rb", ".go", ".c", ".cpp", ".java", ".sh", ".ps1", ".md",
                    ]) and full_element_url not in all_scannable_urls:
                        all_scannable_urls.add(full_element_url)
                        if verbose:
                            print(f" + (Scan) {full_element_url}")

            print(f"\n--------- unique scannable files: {len(all_scannable_urls)} ---------")
            for file_url in sorted(list(all_scannable_urls)):
                print(f" - {file_url}")

            def extract_loose_links_from_content(content, base_url):
                """
                Extracts various link formats (loose, concatenated, obfuscated) from text content.
                """
                links = set()

                # Basic HTTP/HTTPS links
                links.update(re.findall(r'(https?://[^\s"\'<>]+)', content))
                # Double-slash links
                links.update(re.findall(r'(?<!:)//[^\s"\'<>]+', content))
                # Relative paths
                links.update(re.findall(r'(?<!:)\/[a-zA-Z0-9_\-/\.]+', content))
                # Domains with common TLDs
                links.update(re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+(?:' + '|'.join([tld.lstrip('.') for tld in COMMON_TLDS]) + r')\b', content))
                # De-obfuscated domains
                links.update(re.findall(r'\b(?:[a-zA-Z0-9-]+\[\.\](?:[a-z]{2,4}))\b', content))
                # Hex-encoded URLs
                links.update(re.findall(r'hxxps?://[^\s"\']+', content))
                # Concatenated strings
                concat_matches = re.findall(r'"([a-zA-Z0-9-]{3,})"\s*\+\s*"(\.(?:' + '|'.join([tld.lstrip('.') for tld in COMMON_TLDS]) + r'))"', content)
                for part1, part2 in concat_matches:
                    links.add(part1 + part2)
                
                # Normalize all found links
                normalized_links = set()
                for link in links:
                    normalized_links.add(normalize_url(base_url, link))

                return normalized_links

            # Recursive file scanner
            async def process_file_content(file_url, current_depth):
                """
                Recursively processes file content and searches for links and TLDs within them.
                """
                if file_url in visited_scannable_urls or current_depth > max_depth:
                    return
                visited_scannable_urls.add(file_url)

                if verbose:
                    print(f"\n└── [Depth {current_depth}] Processing: {file_url}")

                try:
                    response = await page.request.get(file_url, timeout=30000, headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Referer": url,
                        "X-Requested-With": "XMLHttpRequest"
                    })

                    print(f"    ├── [Status {response.status}] {file_url}")

                    content_type = response.headers.get("content-type", "").lower()
                    if response.ok and ("text" in content_type or "json" in content_type or "javascript" in content_type or "xml" in content_type or "svg" in content_type):
                        content = await response.text()
                        first_line = content.strip().split("\n")[0][:200].lower()

                        if any(k in first_line for k in ["access denied", "captcha", "<!doctype", "cloudflare"]):
                            print(f"└── [BLock] Possibly blocked or redirected: {file_url}")
                            print(f"    First line: {first_line[:100]}")
                            return

                        all_found_links_in_content = extract_loose_links_from_content(content, file_url)
                        
                        if all_found_links_in_content:
                            print(f"\n└── [TLD]: {file_url}")
                            scannable_sub_urls = []
                            for link in all_found_links_in_content:
                                if not filter_word or filter_word.lower() in link.lower():
                                    if link not in found_links:
                                        print(f"  ├── {link}") 
                                    found_links.add(link)
                                    
                                    path_for_recursion = link.lower().split('?')[0].split('#')[0]
                                    if any(path_for_recursion.endswith(ext) for ext in [
                                        ".js", ".css", ".json", ".txt", ".xml", ".html", ".svg",
                                        ".ts", ".jsx", ".tsx", ".vue", ".php", ".asp", ".aspx", ".jsp",
                                        ".py", ".rb", ".go", ".c", ".cpp", ".java", ".sh", ".ps1", ".md",
                                    ]) and link not in all_scannable_urls:
                                        scannable_sub_urls.append(link)

                            for sub_url in scannable_sub_urls:
                                await process_file_content(sub_url, current_depth + 1)
                        else:
                             if verbose:
                                 print(f"   └──[TLD-Not-Found]: {file_url}")
                    else:
                        if verbose:
                            print(f"    └── [Warning-Skip]: {file_url} No text content, skip.")
                except Exception as e:
                    print(f"    └── [Error-File] {file_url}: {e}")

            print(f"\n--------- Recursive scanning begins (depth: {max_depth})... ---------")
            for file_url in list(all_scannable_urls):
                await process_file_content(file_url, current_depth=1)

    except asyncio.CancelledError:
        pass
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
    finally:
        if browser and browser.is_connected():
            try:
                await browser.close()
                if verbose:
                    print("└── [success-Brwoser-Close] (finally block).")
            except Exception as e:
                print(f"└── [Error-Brwoser-Close] (finally block): {e}")
        
        if not shutdown_initiated:
            try:
                new_links_to_write = sorted(list(found_links - existing_links_in_file))
                if new_links_to_write:
                    with open(output_file, "a", encoding="utf-8") as f:
                        for link in new_links_to_write:
                            f.write(link + "\n")
                    print(f"\nGenerated List: {len(new_links_to_write)}")
                else:
                    print("\n[Link-Not-Add]")
                #print(f"Final number of unique links: {len(found_links)}")
                print(f"Save/Update in FIle: {output_file}")
            except Exception as file_write_error:
                print(f"[Error-Files-Write] (finally block): {file_write_error}")


if __name__ == "__main__":
    asyncio.run(main())
