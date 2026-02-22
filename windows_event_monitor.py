import win32evtlog
from collections import defaultdict, deque
from datetime import datetime, timedelta

FAILED_LOGIN = 4625
SUCCESS_LOGIN = 4624

class WindowsSecurityMonitor:
    def __init__(self, alert_callback):
        self.alert_callback = alert_callback
        self.failed_attempts = defaultdict(lambda: deque())
        self.bruteforce_alerted = set()

        self.server = 'localhost'
        self.log_type = 'Security'
        self.last_record_number = 0

    def check_events(self):
        hand = win32evtlog.OpenEventLog(self.server, self.log_type)
        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        events = win32evtlog.ReadEventLog(hand, flags, 0)

        if not events:
            return

        for event in events:
            record_number = event.RecordNumber

            # ✅ Skip already processed events
            if record_number <= self.last_record_number:
                continue

            self.last_record_number = record_number

            event_id = event.EventID & 0xFFFF

            if not event.StringInserts:
                continue

            try:
                user = str(event.StringInserts[5])
            except:
                user = "Unknown"

            if event_id == FAILED_LOGIN:
                self.track_failed_login(user)

            elif event_id == SUCCESS_LOGIN:
                self.check_success_after_fail(user)

    def track_failed_login(self, user):
        now = datetime.now()
        attempts = self.failed_attempts[user]
        attempts.append(now)

        # Keep only last 2 minutes
        while attempts and (now - attempts[0]) > timedelta(minutes=2):
            attempts.popleft()

        # Trigger only once per window
        if len(attempts) >= 5 and user not in self.bruteforce_alerted:
            self.alert_callback(
                f"Possible brute-force attack on user '{user}' "
                f"({len(attempts)} failures in 2 minutes)",
                "HIGH",
                "SYSTEM"
            )
            self.bruteforce_alerted.add(user)

    def check_success_after_fail(self, user):
        attempts = self.failed_attempts[user]

        if len(attempts) >= 5:
            self.alert_callback(
                f"User '{user}' logged in after multiple failures → possible compromise",
                "CRITICAL",
                "SYSTEM"
            )

        # Reset tracking after success
        self.failed_attempts[user].clear()
        self.bruteforce_alerted.discard(user)