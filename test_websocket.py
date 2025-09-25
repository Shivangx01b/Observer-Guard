#!/usr/bin/env python3
"""
WebSocket Testing for ObserveGuard Real-time Threat Detection
Demonstrates real-time monitoring capabilities
"""

import asyncio
import websockets
import json
import threading
import time
import sys
import os
from pathlib import Path

class WebSocketTester:
    def __init__(self, base_url="ws://localhost:8080"):
        self.base_url = base_url
        self.received_events = []
        self.received_threats = []
        self.received_alerts = []
        self.received_metrics = []

    async def listen_to_events(self, duration=30):
        """Listen to real-time events"""
        uri = f"{self.base_url}/ws/events"
        print(f"🔗 Connecting to events stream: {uri}")

        try:
            async with websockets.connect(uri) as websocket:
                print("✅ Connected to events stream")

                # Send filter for AI security events
                filter_message = {
                    "type": "set_filters",
                    "filters": {
                        "event_types": ["ai_security", "process", "network", "file"]
                    }
                }
                await websocket.send(json.dumps(filter_message))

                start_time = time.time()
                while time.time() - start_time < duration:
                    try:
                        message = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                        data = json.loads(message)

                        if data.get('type') == 'event':
                            self.received_events.append(data)
                            event_data = data.get('data', {})
                            event_type = event_data.get('type', 'unknown')
                            process = event_data.get('process', 'unknown')
                            print(f"📊 Event: {event_type} from {process}")
                        elif data.get('type') == 'welcome':
                            print(f"👋 {data.get('data', {}).get('message', 'Connected')}")
                        elif data.get('type') == 'filters_updated':
                            print("🔧 Filters updated successfully")
                    except asyncio.TimeoutError:
                        continue
                    except websockets.exceptions.ConnectionClosed:
                        print("❌ Events connection closed")
                        break

        except Exception as e:
            print(f"❌ Events connection error: {e}")

    async def listen_to_threats(self, duration=30):
        """Listen to real-time threats"""
        uri = f"{self.base_url}/ws/threats"
        print(f"🔗 Connecting to threats stream: {uri}")

        try:
            async with websockets.connect(uri) as websocket:
                print("✅ Connected to threats stream")

                start_time = time.time()
                while time.time() - start_time < duration:
                    try:
                        message = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                        data = json.loads(message)

                        if data.get('type') == 'threat':
                            self.received_threats.append(data)
                            threat_data = data.get('data', {})
                            severity = threat_data.get('severity', 'unknown')
                            category = threat_data.get('category', 'unknown')
                            print(f"🚨 THREAT: {severity.upper()} - {category}")
                        elif data.get('type') == 'welcome':
                            print(f"👋 {data.get('data', {}).get('message', 'Connected')}")
                    except asyncio.TimeoutError:
                        continue
                    except websockets.exceptions.ConnectionClosed:
                        print("❌ Threats connection closed")
                        break

        except Exception as e:
            print(f"❌ Threats connection error: {e}")

    async def listen_to_metrics(self, duration=30):
        """Listen to real-time metrics"""
        uri = f"{self.base_url}/ws/metrics"
        print(f"🔗 Connecting to metrics stream: {uri}")

        try:
            async with websockets.connect(uri) as websocket:
                print("✅ Connected to metrics stream")

                start_time = time.time()
                while time.time() - start_time < duration:
                    try:
                        message = await asyncio.wait_for(websocket.recv(), timeout=2.0)
                        data = json.loads(message)

                        if data.get('type') == 'metrics':
                            self.received_metrics.append(data)
                            metrics_data = data.get('data', {})
                            event_counts = metrics_data.get('event_counts', {})
                            threat_counts = metrics_data.get('threat_counts', {})
                            system_stats = metrics_data.get('system_stats', {})

                            total_events = sum(event_counts.values())
                            total_threats = sum(threat_counts.values())
                            cpu_usage = system_stats.get('cpu_usage', 0)

                            print(f"📈 Metrics: {total_events} events, {total_threats} threats, CPU: {cpu_usage}%")
                        elif data.get('type') == 'welcome':
                            print(f"👋 {data.get('data', {}).get('message', 'Connected')}")
                    except asyncio.TimeoutError:
                        continue
                    except websockets.exceptions.ConnectionClosed:
                        print("❌ Metrics connection closed")
                        break

        except Exception as e:
            print(f"❌ Metrics connection error: {e}")

    def generate_suspicious_activity(self, duration=25):
        """Generate suspicious activity to trigger alerts"""
        print("🎭 Generating suspicious activity...")

        def activity_loop():
            start_time = time.time()
            counter = 0

            while time.time() - start_time < duration:
                try:
                    counter += 1

                    # Create suspicious model files
                    if counter % 3 == 0:
                        model_file = Path(f"suspicious_model_{counter}.pt")
                        with open(model_file, 'wb') as f:
                            f.write(b'0' * (1024 * 1024))  # 1MB fake model

                        # Read it back (simulating access)
                        with open(model_file, 'rb') as f:
                            f.read(1024)

                        model_file.unlink()
                        print(f"🔍 Generated model access activity #{counter}")

                    # Create large files (simulating data exfiltration)
                    if counter % 5 == 0:
                        large_file = Path(f"exfil_data_{counter}.tmp")
                        with open(large_file, 'wb') as f:
                            f.write(b'X' * (2 * 1024 * 1024))  # 2MB file

                        large_file.unlink()
                        print(f"📤 Generated data exfiltration simulation #{counter}")

                    time.sleep(2)

                except Exception as e:
                    print(f"⚠️ Activity generation error: {e}")

            print("✅ Suspicious activity generation completed")

        activity_thread = threading.Thread(target=activity_loop)
        activity_thread.daemon = True
        activity_thread.start()
        return activity_thread

    async def test_all_streams(self, test_duration=30):
        """Test all WebSocket streams simultaneously"""
        print("🚀 Starting WebSocket Real-time Monitoring Test")
        print("=" * 60)
        print(f"Duration: {test_duration} seconds")
        print("This will connect to all WebSocket streams and generate suspicious activity")
        print()

        # Start suspicious activity generator
        activity_thread = self.generate_suspicious_activity(test_duration - 5)

        # Start all WebSocket connections concurrently
        tasks = [
            asyncio.create_task(self.listen_to_events(test_duration)),
            asyncio.create_task(self.listen_to_threats(test_duration)),
            asyncio.create_task(self.listen_to_metrics(test_duration))
        ]

        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            print("\n🛑 Test interrupted by user")

        # Wait for activity thread to complete
        if activity_thread.is_alive():
            activity_thread.join(timeout=5)

        # Print summary
        self.print_results()

    def print_results(self):
        """Print test results summary"""
        print("\n" + "=" * 60)
        print("📊 WEBSOCKET TEST RESULTS")
        print("=" * 60)

        print(f"📊 Events received: {len(self.received_events)}")
        print(f"🚨 Threats received: {len(self.received_threats)}")
        print(f"🚨 Alerts received: {len(self.received_alerts)}")
        print(f"📈 Metrics updates: {len(self.received_metrics)}")

        if self.received_events:
            print(f"\n📋 Event Types Detected:")
            event_types = {}
            for event in self.received_events:
                event_type = event.get('data', {}).get('type', 'unknown')
                event_types[event_type] = event_types.get(event_type, 0) + 1

            for event_type, count in event_types.items():
                print(f"   • {event_type}: {count}")

        if self.received_threats:
            print(f"\n🚨 Threat Categories:")
            threat_categories = {}
            for threat in self.received_threats:
                category = threat.get('data', {}).get('category', 'unknown')
                threat_categories[category] = threat_categories.get(category, 0) + 1

            for category, count in threat_categories.items():
                print(f"   • {category}: {count}")

        if self.received_metrics:
            last_metrics = self.received_metrics[-1].get('data', {})
            print(f"\n📈 Final System Metrics:")
            print(f"   • Event Counts: {last_metrics.get('event_counts', {})}")
            print(f"   • Threat Counts: {last_metrics.get('threat_counts', {})}")
            print(f"   • System Stats: {last_metrics.get('system_stats', {})}")

        print(f"\n🎉 WebSocket real-time monitoring test completed!")

        if len(self.received_events) > 0:
            print("✅ Real-time event streaming is working")
        else:
            print("⚠️ No events received - ensure collector is running")

        if len(self.received_metrics) > 0:
            print("✅ Real-time metrics streaming is working")

def main():
    """Main test function"""
    print("🛡️ ObserveGuard WebSocket Real-time Monitoring Test")
    print("=" * 60)
    print("This test will:")
    print("• Connect to all WebSocket streams")
    print("• Generate suspicious activity")
    print("• Monitor real-time threat detection")
    print("• Report on streaming capabilities")
    print()

    # Check if websockets is available
    try:
        import websockets
    except ImportError:
        print("❌ websockets library not found. Install with:")
        print("   pip install websockets")
        sys.exit(1)

    print("⚠️ Make sure ObserveGuard API server is running:")
    print("   ./build/observeguard server --config configs/apiserver.yaml")
    print()

    input("Press Enter to start the test...")

    tester = WebSocketTester()

    try:
        asyncio.run(tester.test_all_streams(30))
    except KeyboardInterrupt:
        print("\n🛑 Test interrupted")
    except Exception as e:
        print(f"❌ Test error: {e}")
        print("\nTroubleshooting:")
        print("• Ensure the API server is running")
        print("• Check firewall settings")
        print("• Verify WebSocket support")

if __name__ == "__main__":
    main()