import socket
import argparse
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Analyzes FTP traffic for security vulnerabilities.",
                                     epilog="Example usage: python net_ftp_analyzer.py ftp.example.com")
    parser.add_argument("host", help="The FTP server hostname or IP address.")
    parser.add_argument("-p", "--port", type=int, default=21, help="The FTP server port (default: 21).")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    parser.add_argument("-a", "--anonymous", action="store_true", help="Attempt anonymous login.")
    return parser.parse_args()

def check_anonymous_login(host, port):
    """
    Attempts to log in to the FTP server anonymously.

    Args:
        host (str): The FTP server hostname or IP address.
        port (int): The FTP server port.

    Returns:
        bool: True if anonymous login is successful, False otherwise.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)  # Set a timeout to prevent indefinite hanging
        s.connect((host, port))

        response = s.recv(1024).decode('utf-8', errors='ignore')
        logging.debug(f"Initial FTP response: {response.strip()}")

        # Each step trusts a single recv to hold the whole reply. A
        # multi line greeting or a reply split across packets can put
        # something other than the code at the front of the buffer, and
        # the startswith checks below then read the wrong thing. I also
        # require 331 here, so a server that logs anonymous in at once
        # with a 230 after USER gets reported as blocked, not open.
        # Send USER command
        s.send(b"USER anonymous\r\n")
        response = s.recv(1024).decode('utf-8', errors='ignore')
        logging.debug(f"USER response: {response.strip()}")
        if not response.startswith("331"):  # Check for "Password required"
           logging.warning("Anonymous login might be blocked by the server. Server did not request password. Check response code")
           s.close()
           return False

        # Send PASS command
        s.send(b"PASS anonymous@example.com\r\n")
        response = s.recv(1024).decode('utf-8', errors='ignore')
        logging.debug(f"PASS response: {response.strip()}")

        if response.startswith("230"):  # Check for "User logged in"
            logging.info("Anonymous login successful!")
            s.send(b"QUIT\r\n") # clean disconnect
            s.close()
            return True
        else:
            logging.info("Anonymous login failed.")
            s.close()
            return False

    except socket.timeout:
        logging.error("Connection timed out.")
        return False
    except socket.error as e:
        logging.error(f"Socket error: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False

# This opens its own connection, separate from the login check, and
# main throws the returned banner away: the banner reaches the log
# only, and the server sees two connections for one run.
def banner_grabbing(host, port):
    """
    Performs banner grabbing to gather information about the FTP server.

    Args:
        host (str): The FTP server hostname or IP address.
        port (int): The FTP server port.

    Returns:
        str: The banner information, or None if an error occurs.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((host, port))
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        logging.info(f"FTP Banner: {banner}")
        s.close()
        return banner
    except socket.timeout:
        logging.error("Connection timed out during banner grabbing.")
        return None
    except socket.error as e:
        logging.error(f"Socket error during banner grabbing: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred during banner grabbing: {e}")
        return None

def validate_host(host):
    """
    Validates the host input.  Simple check to prevent obvious errors.  More validation could be added.

    Args:
        host (str): The host string to validate.

    Returns:
        bool: True if the host is valid, False otherwise.
    """
    if not host:
        logging.error("Host cannot be empty.")
        return False
    if not isinstance(host, str):
        logging.error("Host must be a string.")
        return False
    return True
def validate_port(port):
    """
    Validates the port input. Checks if the port is an integer and within the valid range (1-65535).

    Args:
        port (int): The port number to validate.

    Returns:
        bool: True if the port is valid, False otherwise.
    """
    if not isinstance(port, int):
        logging.error("Port must be an integer.")
        return False
    if not 1 <= port <= 65535:
        logging.error("Port must be between 1 and 65535.")
        return False
    return True


def main():
    """
    Main function to execute the FTP analyzer.
    """
    args = setup_argparse()

    host = args.host
    port = args.port

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)  # Enable debug logging

    # Input Validation
    if not validate_host(host):
        sys.exit(1)
    if not validate_port(port):
        sys.exit(1)

    # Whatever the checks find, main returns and the process exits 0.
    # A refused anonymous login and a timeout look the same to a script
    # watching the exit code; the log lines are the only result.
    logging.info(f"Analyzing FTP server: {host}:{port}")

    # Banner Grabbing
    banner_grabbing(host, port)

    # Anonymous Login Check
    if args.anonymous:
        check_anonymous_login(host, port)


if __name__ == "__main__":
    main()