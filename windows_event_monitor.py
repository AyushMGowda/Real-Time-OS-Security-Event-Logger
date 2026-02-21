import win32evtlog
from collections import defaultdict, deque
from datetime import datetime, timedelta

FAILED_LOGIN = 4625
SUCCESS_LOGIN = 4624

class WindowsSecurityMonitor:
    def __init__(self, alert_callback):
        self.alert_callback = alert_callback
        self.failed_attempts = defaultdict(lambda: deque())

        self.server = 'localhost'
        self.log_type = 'Security'

    def check_events(self):
        hand = win32evtlog.OpenEventLog(self.server, self.log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        events = win32evtlog.ReadEventLog(hand, flags, 0)

        if events:
            for event in events:
                event_id = event.EventID & 0xFFFF
                time_generated = event.TimeGenerated.Format()

                if event_id == FAILED_LOGIN:
                    user = str(event.StringInserts[5]) if event.StringInserts else "Unknown"
                    self.track_failed_login(user, time_generated)

                elif event_id == SUCCESS_LOGIN:
                    user = str(event.StringInserts[5]) if event.StringInserts else "Unknown"
                    self.check_success_after_fail(user, time_generated)

    def track_failed_login(self, user, time_generated):
        now = datetime.now()
        attempts = self.failed_attempts[user]
        attempts.append(now)

        # keep only last 2 minutes
        while attempts and (now - attempts[0]) > timedelta(minutes=2):
            attempts.popleft()

        if len(attempts) >= 5:
            self.alert_callback(
                f"[HIGH] Possible brute-force attack on user '{user}' ({len(attempts)} failures in 2 min)"
            )

    def check_success_after_fail(self, user, time_generated):
        attempts = self.failed_attempts[user]

        if len(attempts) >= 5:
            self.alert_callback(
                f"[CRITICAL] User '{user}' logged in after multiple failures → possible compromise"
            )
            attempts.clear()
