# To profile code

import cProfile
import pstats

def run_with_profiling(miner):
    cProfile.run('miner.start_miner()', 'miner.profile')

    p = pstats.Stats('miner.profile')
    p.sort_stats('cumulative').print_stats(20) # print 20 top functions
# inside main() function

    if os.environ.get('PROFILE', 'false').lower() == 'true':
      run_with_profiling(miner)
      return # exit after profiling
    else:
      miner.start_miner()
