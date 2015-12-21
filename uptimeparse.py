import re

PARSE_REGEX = '^.* up (.*), .* user[s]?, .* load average: (.*), (.*), (.*)$'


class ParsingError(Exception):
    pass


class Uptime(object):

    days = 0
    hours = 0
    minutes = 0
    load1 = None
    load2 = None
    load3 = None
    uptime_string = None

    def __init__(self, uptime_string):
        try:
            u = re.match(PARSE_REGEX, uptime_string.strip())
            if u:
                ug = u.groups()
                self.uptime_string = ug[0]
                self.load1 = float(ug[1])
                self.load2 = float(ug[2])
                self.load3 = float(ug[3])

                if ":" in self.uptime_string:
                    # Uptime has hours
                    x = re.search('(\d{1,2}):(\d{1,2})', self.uptime_string)
                    if x:
                        xg = x.groups()
                        self.hours = int(xg[0])
                        self.minutes = int(xg[1])
                    else:
                        raise ParsingError('Could not parse hours:minutes out of string we thought had hours:minutes.')

                if 'days' in self.uptime_string:
                    x = re.search('(\d*) day', self.uptime_string)
                    if x:
                        xg = x.groups()
                        self.days = int(xg[0])
                    else:
                        raise ParsingError('Could not parse days out of string we thought had days.')

                if " min" in self.uptime_string:
                    # Uptime has minutes
                    x = re.search('(\d*) min', self.uptime_string)
                    if x:
                        xg = x.groups()
                        self.minutes = int(xg[0])
                    else:
                        raise ParsingError('Could not parse minutes out a string we thought had minutes.')

        except Exception, e:
            raise ParsingError('General Parsing Error: %s' % e)

    def __str__(self):
        return 'Uptime: %s days, %s hours, %s minutes - Load Average: %s %s %s' \
               % (self.days, self.hours, self.minutes, self.load1, self.load2, self.load3)

    def total_minutes(self):
        return (self.days * 24 * 60) + (self.hours * 60) + self.minutes


if __name__ == "__main__":
    print 'Uptime Parsing Demo: '

    print(Uptime("06:35:13 up 3 days, 23:31,  0 users,  load average: 0.00, 0.01, 0.05"))
    print(Uptime("06:31:20 up 22:16,  0 users,  load average: 0.00, 0.01, 0.05"))
    print(Uptime("06:11:38 up 9 min,  0 users,  load average: 0.00, 0.02, 0.02"))
    print(Uptime("06:11:38 up 14 days, 9 min,  0 users,  load average: 0.00, 0.02, 0.02"))

    example = Uptime("06:35:13 up 3 days, 23:31,  0 users,  load average: 0.00, 0.01, 0.05")
    print "Total Minutes: %s" % example.total_minutes()
