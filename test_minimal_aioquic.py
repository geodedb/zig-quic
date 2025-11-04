#!/usr/bin/env python3
"""
Minimal QUIC test - just establish connection and check handshake completion
"""
import asyncio
import logging
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, HandshakeCompleted, ConnectionTerminated

logging.basicConfig(level=logging.DEBUG, format='%(levelname)s:%(name)s:%(message)s')
logger = logging.getLogger(__name__)


class TestProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.handshake_complete = asyncio.Event()
        self.terminated = asyncio.Event()
    
    def quic_event_received(self, event: QuicEvent) -> None:
        logger.info(f"Event: {event}")
        if isinstance(event, HandshakeCompleted):
            logger.info("✅ Handshake COMPLETED!")
            self.handshake_complete.set()
        elif isinstance(event, ConnectionTerminated):
            logger.info(f"Connection terminated: {event}")
            self.terminated.set()


async def main():
    config = QuicConfiguration(
        is_client=True,
        verify_mode=0,
        alpn_protocols=["echo", "hq-interop"],
    )
    
    logger.info("Connecting to 127.0.0.1:4433...")
    
    async with connect(
        "127.0.0.1",
        4433,
        configuration=config,
        create_protocol=TestProtocol,
    ) as client:
        logger.info("✅ Connection object created")
        
        # Wait for handshake
        try:
            await asyncio.wait_for(client.handshake_complete.wait(), timeout=5.0)
            logger.info("✅ Handshake completed successfully")
            
            # Now try to send a STREAM frame
            quic = client._quic
            stream_id = quic.get_next_available_stream_id()
            logger.info(f"Opening stream {stream_id}...")
            
            test_data = b"TEST DATA\n"
            quic.send_stream_data(stream_id, test_data, end_stream=False)
            client.transmit()
            logger.info(f"📤 Sent {len(test_data)} bytes on stream {stream_id}")
            
            # Wait a bit
            await asyncio.sleep(2.0)
            logger.info("Test complete")
            
        except asyncio.TimeoutError:
            logger.error("❌ Handshake timeout")


if __name__ == "__main__":
    asyncio.run(main())
