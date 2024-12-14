import multiprocessing
import time

class BitcoinSoloMiner:

    def __init__(self, config, best_hash, best_hash_difficulty, total_hashes, lock):
        #...
        self.best_hash = best_hash
        self.best_hash_difficulty = best_hash_difficulty
        self.total_hashes = total_hashes
        self.lock = lock
        #...

    def mine_block(self):
        #...
        # remove the best hash calculation and display
        # from here, as now it will be in the child process
        with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
             nonce = 0
             while True:
               nonces = range(nonce, nonce + 1000) # Adjust this number for optimal balance
               results = pool.map(self.calculate_and_check_hash, nonces) # uses map instead of apply_async
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
            self.total_hashes.value +=1 # lock to add totals
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


def main():
    #...
    manager = multiprocessing.Manager()
    best_hash = manager.Value('s', "")
    best_hash_difficulty = manager.Value('d', 0)
    total_hashes = manager.Value('i', 0)
    lock = manager.Lock()

    miner = BitcoinSoloMiner(config, best_hash, best_hash_difficulty, total_hashes, lock)
    miner.start_miner()
