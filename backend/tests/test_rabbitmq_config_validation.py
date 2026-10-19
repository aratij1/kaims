import pytest
from pydantic import ValidationError
from common.config import Settings

@pytest.mark.parametrize("key,value", [
 ("RABBITMQ_CONSUMER_PREFETCH_COUNT",0), ("RABBITMQ_CONSUMER_PREFETCH_COUNT",-1),
 ("RABBITMQ_HANDLER_TIMEOUT_SECONDS",0), ("RABBITMQ_HANDLER_TIMEOUT_SECONDS",-1),
 ("RABBITMQ_CONSUMER_MAX_RETRIES",-1),
 ("RABBITMQ_TRANSIENT_MAX_REQUEUES",-1), ("RABBITMQ_TRANSIENT_MAX_REQUEUES",21),
 ("RABBITMQ_PUBLISHER_CHANNEL_POOL_SIZE",0), ("RABBITMQ_PUBLISHER_CHANNEL_POOL_SIZE",-1),
])
def test_unsafe_transport_settings_fail_at_startup(key,value):
    with pytest.raises(ValidationError): Settings(**{key:value})

def test_zero_retries_and_small_positive_timeout_are_supported():
    settings=Settings(RABBITMQ_CONSUMER_MAX_RETRIES=0,RABBITMQ_HANDLER_TIMEOUT_SECONDS=0.05,RABBITMQ_CONSUMER_PREFETCH_COUNT=1)
    assert settings.rabbitmq_consumer_max_retries==0
    assert settings.rabbitmq_handler_timeout_seconds==0.05
