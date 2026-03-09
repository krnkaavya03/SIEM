import win32evtlog
import datetime

class WindowsEventCollector:
    """
    Collects real-time events from Windows Event Logs
    """

    def __init__(self, channel="Security"):
        self.channel = channel
        self.server = "localhost"
        self.flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        self.last_record_number = None

    def collect_new_events(self):
        """
        Returns new log entries since last poll
        """
        log_entries = []

        hand = win32evtlog.OpenEventLog(self.server, self.channel)
        total = win32evtlog.GetNumberOfEventLogRecords(hand)

        events = win32evtlog.ReadEventLog(hand, self.flags, 0)

        for event in events:
            if self.last_record_number and event.RecordNumber <= self.last_record_number:
                continue  # Skip already processed

            timestamp = event.TimeGenerated.Format()  # e.g., '02/15/2026 15:30:01'
            timestamp = datetime.datetime.strptime(timestamp, "%m/%d/%Y %H:%M:%S")

            # Basic fields
            log_entries.append({
                "timestamp": timestamp,
                "event_id": event.EventID,
                "source": event.SourceName,
                "category": event.EventCategory,
                "username": str(event.StringInserts[1]) if event.StringInserts and len(event.StringInserts) > 1 else "N/A",
                "ip_address": "N/A",  # Usually not in Windows logs
                "info": " | ".join(event.StringInserts) if event.StringInserts else "",
                "raw_event": event
            })

            self.last_record_number = event.RecordNumber

        return log_entries
