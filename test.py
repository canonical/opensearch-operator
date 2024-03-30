import logging
import sys

from tenacity import retry, wait_fixed, retry_if_exception_type


logger = logging.getLogger("retry_logger")

# Closure factory for custom_before_sleep
def custom_log_before_sleep(logger, *args, **kwargs):
    def log_error(retry_state):
        logger.error(f"Before sleep: Attempt {retry_state.attempt_number}, Args: {args}, Kwargs: {kwargs}, Error: {retry_state.outcome.exception()}")
    return log_error

# Example retrying function
@retry(wait=wait_fixed(1), before_sleep=make_custom_before_sleep(logger, 'extra_arg1', key1='value1'))
def unreliable_function():
    logger.info("Trying...")
    raise Exception("Something went wrong, as expected.")

# Running the example
try:
    unreliable_function()
except Exception as e:
    print("Final failure after retries: %s", e)