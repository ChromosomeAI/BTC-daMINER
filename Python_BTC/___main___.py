import requests
import colorama
from tabulate import tabulate
import time
import hashlib
import json
import logging
import argparse
import configparser
import multiprocessing
import os

colorama.init()

# Logging setup
logging.basicConfig(
    level=logging.INFO,  # Set default to info level for normal operation
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("miner.log"), # Save logs to file
        logging.StreamHandler() # show logs in console
    ]
)

class BitcoinSoloMiner:
    def __init__(self, config, best_hash, best_hash_difficulty, total_hashes, lock):
        self.config = config
        self.network = config.get("network", "network")
        self.target = None
        self.extranonce2 = None
        self.coinbase_hash = None
        self.merkle_root = None
        self.difficulty = None
        self.block_height = None
        self.start_time = time.time()
        # Shared variables
        self.best_hash = best_hash
        self.best_hash_difficulty = best_hash_difficulty
        self.total_hashes = total_hashes
        self.lock = lock
        # pre-encode
        self.fixed_header_bytes = None

    def fetch_block_data(self):
        try:
          logging.info(f"Fetching new block from {self.network}...")
          response = requests.get(f"https://blockexplorer.one/api/v1/blocks/latest?network={self.network}")
          response.raise_for_status()  # Raise an exception for bad status codes
          block_data = response.json()
          self.target = block_data["target"]
          self.extranonce2 = block_data["extranonce2"]
          self.coinbase_hash = block_data["coinbase_hash"]
          self.merkle_root = block_data["merkle_root"]
          self.difficulty = int(block_data["difficulty"], 16)
          self.block_height = block_data["height"]
          logging.info(f"New block {self.block_height} found.")
          logging.debug(f"Block Data: {json.dumps(block_data, indent=4)}")

          self.fixed_header_bytes = (
            self.coinbase_hash.encode('utf-8') +
            self.merkle_root.encode('utf-8') +
            self.target.encode('utf-8') +
            self.extranonce2.encode('utf-8')
        )

        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching block data: {e}")
            return False
        except ValueError as e:
          logging.error(f"Error processing block data {e}")
          return False
        return True

    def _calculate_hash(self, nonce):
            try:
                nonce_bytes = str(nonce).encode('utf-8')
                block_header_bytes = self.fixed_header_bytes + nonce_bytes
                block_hash = hashlib.sha256(block_header_bytes).digest()
                return block_hash.hex()
            except Exception as e:
                logging.error(f"Error calculating hash: {e}")
                return None

    def mine_block(self):
        logging.info("Solo Miner Active")
        logging.info(f"Target: {self.target}")
        logging.info(f"Extranonce2: {self.extranonce2}")
        logging.info(f"Coinbase Hash: {self.coinbase_hash}")
        logging.info(f"Merkle Root: {self.merkle_root}")
        logging.info(f"Diff: {self.difficulty}")

        with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
            nonce = 0
            while True:
                nonces = range(nonce, nonce + 1000) # Adjust this number for optimal balance
                results = pool.map(self.calculate_and_check_hash, nonces)
                # check if any block was found, in order to exit
                if any(results):
                  return
                nonce += 1000
                if nonce % 100000 == 0:
                    self._display_hashrate()
                    # check if other processes are also checking
                    # and if so, exit gracefully
                    if not self.lock.acquire(block=False):
                      logging.info("Exiting...")
                      return
    def calculate_and_check_hash(self, nonce):
        block_hash_hex = self._calculate_hash(nonce)
        if block_hash_hex is None:
          return False  # Exit if hash calculation fails

        with self.lock:
            self.total_hashes.value += 1 # lock to add totals
            best_hash_int = int(self.best_hash.value, 16) if self.best_hash.value else float('inf')
            current_hash_int = int(block_hash_hex, 16)
            if current_hash_int < best_hash_int:
                self.best_hash.value = block_hash_hex
                self.best_hash_difficulty.value = self._calculate_difficulty(current_hash_int)
                self._show_best_hash_update() # only the best should log the update
            if int(block_hash_hex, 16) < int(self.target, 16):
              logging.info(colorama.Fore.GREEN + f"SOLVED BLOCK! {block_hash_hex}" + colorama.Style.RESET_ALL)
              return True  # Exit if block is found
        return False

    def _calculate_difficulty(self, hash_int):
        """Calculates the difficulty of a hash.

        Args:
            hash_int (int): The integer representation of the hash.

        Returns:
           float: The difficulty of the hash.
        """
        return (2**256) / hash_int if hash_int else 0

    def _display_hashrate(self):
            """Displays the current hashrate."""
            elapsed_time = time.time() - self.start_time
            if elapsed_time > 0:
                hash_rate = self.total_hashes.value / elapsed_time
            else:
                hash_rate = 0
            logging.info(f"Total Hashes: {self.total_hashes.value} | Hash Rate: {hash_rate:.2f} H/s")

    def _show_best_hash_update(self):
      """Logs the new best hash and difficulty"""
      logging.info(f"[BEST HASH UPDATE] New best hash: {self.best_hash.value} with difficulty: {self.best_hash_difficulty.value} ")
      self._display_hashrate()


    def start_miner(self):
        while True:
            if not self.fetch_block_data():
              logging.error("Unable to fetch block data, please check your connection and configurations")
              time.sleep(10)  # sleep 10 seconds before trying again
            else:
              self.mine_block()
              # restart loop
              logging.info("Miner restarting...")
              self.total_hashes.value = 0
              self.start_time = time.time()
              self.best_hash.value = ""
              self.best_hash_difficulty.value = 0

def load_config(config_path):
    """Loads configurations from file

    Args:
        config_path (str): configuration file path
    Returns:
        dict: dictionary with config values
    """
    config = configparser.ConfigParser()
    config.read(config_path)
    return dict(config["DEFAULT"]) if "DEFAULT" in config else {}

def main():
    parser = argparse.ArgumentParser(description="Bitcoin Solo Miner")
    parser.add_argument(
        "--config", type=str, default="config.ini", help="Path to the configuration file"
    )
    parser.add_argument(
        "--log_level", type=str, default="INFO", help="set the log level: DEBUG, INFO, WARNING, ERROR"
    )
    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)

    # Set log level, if provided
    log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    logging.getLogger().setLevel(log_level)

    manager = multiprocessing.Manager()
    best_hash = manager.Value('s', "")
    best_hash_difficulty = manager.Value('d', 0)
    total_hashes = manager.Value('i', 0)
    lock = manager.Lock()

    miner = BitcoinSoloMiner(config, best_hash, best_hash_difficulty, total_hashes, lock)

    if os.environ.get('PROFILE', 'false').lower() == 'true':
      run_with_profiling(miner)
      return # exit after profiling
    else:
      miner.start_miner()

def run_with_profiling(miner):
    import cProfile
    import pstats
    cProfile.run('miner.start_miner()', 'miner.profile')

    p = pstats.Stats('miner.profile')
    p.sort_stats('cumulative').print_stats(20) # print 20 top functions

if __name__ == "__main__":
    main()
