import hashlib
def _calculate_hash(self, nonce):
        try:
            block_header_bytes = (
                self.coinbase_hash.encode('utf-8') +
                self.merkle_root.encode('utf-8') +
                self.target.encode('utf-8') +
                self.extranonce2.encode('utf-8') +
                str(nonce).encode('utf-8')
            )

            block_hash = hashlib.sha256(block_header_bytes).digest()
            return block_hash.hex()
        except Exception as e:
            logging.error(f"Error calculating hash: {e}")
            return None
