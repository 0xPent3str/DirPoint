# Dirpoint

Dirpoint is a powerful web reconnaissance tool designed to discover and extract all scannable files and hidden links within a website. Using the `Playwright` library, it simulates a real user's browser, allowing it to bypass some security measures and find dynamically loaded content. The tool is especially useful for penetration testers and security researchers.

## Features

* **Dynamic Scanning:** Simulates browser actions (e.g., scrolling, DOM attribute inspection) to find links that are loaded asynchronously.
* **Comprehensive Link Extraction:** Finds links not only in standard HTML tags (`<a>`, `<script>`, `<link>`) but also in various other attributes (`data-url`, `data-href`), CSS, JavaScript, and other text-based files.
* **Recursive Scanning:** Recursively scans found files (`.js`, `.css`, `.json`, etc.) up to a specified depth to uncover deeper links.
* **URL Normalization:** Automatically handles relative and malformed URLs to create absolute paths.
* **Configurable:** Allows filtering results by keyword, setting recursion depth, and specifying an output file.
* **Shutdown:** Safely stops the process and saves all discovered links when a `Ctrl+C` signal is received.

## Installation

### Prerequisites

You need **Python 3.8** or a newer version installed on your system.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/0xPent3str/DirPoint

    cd dirpoint
    ```

2.  **Install the required Python packages:**
    The script uses `playwright`, which also requires its browsers to be installed.
    ```bash
    pip install playwright
    playwright install
    ```

## Usage

Run the script from the command line with the following arguments:

```bash
python3 dirpoint.py --url <target_url> [options]
