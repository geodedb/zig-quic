#!/usr/bin/env python3
"""
Direct QUIC streaming test using aioquic to validate 1-RTT functionality
"""
import asyncio
import logging
import sys
from typing import Optional, cast

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import QuicEvent, StreamDataReceived, HandshakeCompleted

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EchoClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.response_received = asyncio.Event()
        self.response_data = b""
    
    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, HandshakeCompleted):
            logger.info("✅ Handshake completed")
        elif isinstance(event, StreamDataReceived):
            logger.info(f"📥 Received: {event.data.decode().strip()}")
            self.response_data += event.data
            self.response_received.set()


async def test_quic_echo(host: str, port: int):
    """Test QUIC echo server with bidirectional streaming"""
    
    config = QuicConfiguration(
        is_client=True,
        verify_mode=0,  # Disable certificate verification
        alpn_protocols=["hq-interop"],  # Match server's default ALPN
    )
    
    logger.info(f"Connecting to {host}:{port}...")
    
    try:
        async with connect(
            host,
            port,
            configuration=config,
            create_protocol=EchoClientProtocol,
        ) as client:
            client = cast(EchoClientProtocol, client)
            logger.info("✅ Connection established")
            
            # Wait a bit for handshake
            await asyncio.sleep(0.5)
            
            # Get QUIC connection
            quic = client._quic
            
            # Open a bidirectional stream
            stream_id = quic.get_next_available_stream_id()
            logger.info(f"Opening stream {stream_id}...")
            
            # Send test data
            test_message = b"Hello from aioquic client!\n"
            quic.send_stream_data(stream_id, test_message, end_stream=False)
            client.transmit()
            logger.info(f"📤 Sent: {test_message.decode().strip()}")
            
            # Wait for response with timeout
            try:
                await asyncio.wait_for(client.response_received.wait(), timeout=5.0)
                
                # Verify echo
                if client.response_data == test_message:
                    logger.info("✅ Echo verified! Data matches.")
                    return True
                else:
                    logger.warning(f"⚠️  Echo mismatch. Expected: {test_message}, Got: {client.response_data}")
                    return False
                    
            except asyncio.TimeoutError:
                logger.error("❌ Timeout waiting for response from server")
                return False
            
    except Exception as e:
        logger.error(f"❌ Connection failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    success = await test_quic_echo("127.0.0.1", 4433)
    
    if success:
        print("\n" + "="*50)
        print("✅ SUCCESS: QUIC bidirectional streaming works!")
        print("="*50)
        sys.exit(0)
    else:
        print("\n" + "="*50)
        print("❌ FAILED: QUIC streaming test failed")
        print("="*50)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
