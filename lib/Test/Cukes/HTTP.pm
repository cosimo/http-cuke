package Test::Cukes::HTTP;

use strict;
use warnings;

use HTTP::Cookies ();
use JSON ();
use LWP::UserAgent ();
use Test::Cukes;
use Test::Cukes::JSON;
use Test::More;
use Time::Piece;
use URI ();

our $VERSION = "0.09";

use constant {
    DEFAULT_TIMEOUT       => 60,
    DEFAULT_MAX_REDIRECTS => 5,
    DEFAULT_USER_AGENT    => qq{http-cuke/0.09},
};

our $stash;

sub reset_stash {
    $stash = {
        agent   => undef,
        url     => undef,
        request => {},
    };
}

reset_stash();

sub get_useragent {

    my $ua;

    if ($ua = $stash->{agent}) {
        return $ua;
    }

    $ua = $stash->{agent} ||= LWP::UserAgent->new(
        agent        => DEFAULT_USER_AGENT,
        max_redirect => DEFAULT_MAX_REDIRECTS,
        timeout      => DEFAULT_TIMEOUT,
    );

    # Make sure cookies are kept through requests
    my $jar = HTTP::Cookies->new();
    $ua->cookie_jar($jar);

    return $ua;
}

sub do_request {
    my ($url) = @_;
    $stash->{url} = $url;
    my $ua = get_useragent();
    my $req = HTTP::Request->new("GET" => $url);

    if (my $headers = $stash->{request}->{headers}) {
        for my $k (keys %{$headers}) {
            #diag("Setting header $k to ".$headers->{$k});
            $req->header($k => $headers->{$k});
        }
    }

    if (my $cookies = $stash->{request}->{cookies}) {
        my $host = URI->new($url)->host;
        for (@{ $cookies }) {
            my ($name, $value, $path) = @{ $_ };
            $ua->cookie_jar->set_cookie(undef, $name, $value, $path, $host);
        }
    }

    my $res = $ua->request($req);

    # XXX Should cookies be persistent across requests??
    # delete them here if not
    # --------------------------------------------------

    return ($stash->{res} = $res);
}

sub check_cached {
    my ($stash, $should_be_cached) = @_;

    # Re-request the original URL, it might have been expired
    my $url = $stash->{url};
    my $res = do_request($url);
    if (! $res) {
        return fail("No response object. Maybe you need a 'Given I go to \"<url>\"' first?");
    }

    my $h = $res->headers;
    my $x_varnish = $h->header('X-Varnish');
    my $age = $h->header('Age');
    if ($should_be_cached) {
        like($x_varnish, qr{^ (\d+) \s+ (\d+) $}x,
            "  X-Varnish header contains both current and original XID ($x_varnish)"
        );
        ok(int($age) >= 0,
            "  Age of the cached resource is >= 0 ($age)"
        );
    }
    else {
        like($x_varnish, qr{^ (\d+) $}x,
            "  X-Varnish header contains only current XID ($x_varnish)"
        );
        is(int($age) => 0,
            "  Age of cached resource is zero"
        );
    }
}

sub check_status_code_isnt {
    my ($stash, $expected) = @_;
    my $res = $stash->{res};
    if (! $res) {
        return fail("No response object. Maybe you need a 'Given I go to \"<url>\"' first?");
    }
    return fail($res->message) if _is_internal_error_response($res);
    my $status = $res->status_line;
    if (ref $expected eq "Regexp") {
        unlike($status => $expected,
            "  Status line ($status) should not match expected line ($expected)"
        );
    }
    else {
        my ($status) = $res->status_line =~ m{^(\d+)};
        isnt($status => $expected,
            "  Status code should not be $expected (is $status)"
        );
    }
}

sub check_status_code {
    my ($stash, $expected) = @_;
    my $res = $stash->{res};
    if (! $res) {
        return fail("No response object. Maybe you need a 'Given I go to \"<url>\"' first?");
    }
    return fail($res->message) if _is_internal_error_response($res);
    my $status = $res->status_line;
    if (ref $expected eq "Regexp") {
        like($status => $expected,
            "  Status line ($status) matches expected line ($expected)"
        );
    }
    else {
        my ($status) = $res->status_line =~ m{^(\d+)};
        is($status => $expected,
            "  Status code is $status (expected $expected)"
        );
    }
}

sub page_content_contains {
    my ($stash, $needle) = @_;

    my $res = $stash->{res};
    if (! $res) {
        return fail("No response object. Maybe you need a 'Given I go to \"<url>\"' first?");
    }

    my $body = $res->content;

    if (index($body, $needle) > -1) {
        return 1;
    }

    return;
}

sub check_redirects_chain_for {
    my ($stash, $expected_url) = @_;
    my $res = $stash->{res};
    if (! $res) {
        return fail("No response object. Maybe you need a 'Given I go to \"<url>\"' first?");
    }
    my @redir = $res->redirects;
    if (! @redir) {
        return;
    }

    my $found_redir = 0;

    for (@redir) {
        next unless $_;
        my $uri = $_->header("Location");
        diag("Redirect chain: $uri");
        if ($uri eq $expected_url) {
            $found_redir = 1;
            last;
        }
    }

    return $found_redir;
}

sub _is_internal_error_response {
    my ($res) = @_;
    my $is_success = $res->is_success;
    my $client_warn_header = $res->header('Client-Warning') || '';
    my $internal_response = $client_warn_header eq 'Internal response';
    return ! $is_success && $internal_response;
}

Given qr{(?:i will follow) a max of (\d+) redirects}, sub {
    my $ua = get_useragent();
    $ua->max_redirect($1);
    #diag("Set max redirects to '$1'");
};

Given qr{a timeout of (\d+) seconds}, sub {
    my $ua = get_useragent();
    $ua->timeout($1);
    #diag("Set timeout to '$1'");
};

Given qr{a "(.+)" user agent}, sub {
    my ($new_user_agent) = @_;
    my $ua = get_useragent();
    $ua->agent($new_user_agent);
    #diag("Set user agent to '$new_user_agent'");
};

# Given the HTTP request header "Accept" is "text/html"
Given qr{the HTTP request header "(.+)" is "(.*)"}, sub {
    if (! $stash->{request}) {
        die "Uninitialized request in the stash";
    }
    $stash->{request}->{headers}->{$1} = $2;
    #diag("Set request header $1 to $2");
};

Given qr{the client sends a cookie "(.+)" with value "(.*)"}, sub {
    my ($name, $value) = @_;
    my $path = "/";
    my $cookies = $stash->{request}->{cookies} ||= [];
    push @{ $cookies }, [ $name, $value, $path ];
    return;
};

When qr{I go to "(.+)"}, sub {
    my $url = $1;
    $stash->{url} = $url;
    do_request($url);
};

Then qr{the page should be cached}, sub {
    check_cached($stash, 1);
};

Then qr{the page should not be cached}, sub {
    check_cached($stash, 0);
};

Then qr{I should be redirected to "(.+)"}, sub {
    my $url = $1;
    #diag("Matching redirect chain for '$url'");
    my $found_redir = check_redirects_chain_for($stash, $url);
    ok($found_redir, qq{  Redirect to "$url" was found});
};

Then qr{I should not be redirected to "(.+)"}, sub {
    my $url = $1;
    my $found_redir = check_redirects_chain_for($stash, $url);
    ok(! $found_redir, qq{  Redirect to "$url" was not found});
};

Then qr{the (?:final )HTTP status code should not be "(.+)"}, sub {
    my $http_status = $1;
    return check_status_code_isnt($stash, $http_status);
};

Then qr{the (?:final )HTTP status code should be "(.+)"}, sub {
    my $http_status = $1;
    return check_status_code($stash, $http_status);
};

Then qr{the server should send a "(.+)" cookie}, sub {
    my $res = $stash->{res};
    my $wanted = $1;
    my @cookies = $res->headers->header("Set-Cookie");
    my $found_cookie;
    for (@cookies) {
        if (m{^$wanted\s*=\s*(.+?);}) {
            $found_cookie = $1;
            last;
        }
    }
    ok(defined $found_cookie,"Cookie $wanted was found ($found_cookie)");
};

Then qr{the HTTP response header "(.+)" should not be there}, sub {
    my $res = $stash->{res};
    my $header = $1;
    my $value = $res->headers->header($header);
    is($value, undef,
        "HTTP response header $header isn't defined");
};

Then qr{the HTTP response header "(.+)" should be "(.+)"}, sub {
    my $res = $stash->{res};
    my $header = $1;
    my $expected_value = $2 || q{};
    my $value = $res->headers->header($header) || q{};
    is($value, $expected_value,
        "HTTP response header $header value $value is $expected_value")
        or diag("RESPONSE: " . $res->as_string);
};

Then qr{the HTTP response header "(.+)" should match "(.+)"}, sub {
    my $res = $stash->{res};
    my $header = $1;
    my $expected_value = $2;
    my $value = $res->headers->header($header);
    ok(index($value, $expected_value) > -1,
        "HTTP response header $header value $value matched $expected_value");
};

Then qr{the server should send a CSRF token}, sub {
    my $res = $stash->{res};
    my @cookies = $res->headers->header("Set-Cookie");
    #use Data::Dumper;
    #diag(Dumper(\@cookies));
    my $found_csrf = 0;
    for (@cookies) {
        # Django default format (or TV Store hack by michalj)
        if (m{^csrftoken\s*=\s*(.+?);} or m{^xcsrftoken\s*=\s*(.+?);}) {
            $found_csrf = $1;
            last;
        }
    }
    ok($found_csrf, "  CSRF token was found ($found_csrf)");
};

Then qr{the HTTP status line should match "(.+)"}, sub {
    my $http_status = quotemeta($1);
    my $http_status_re = qr{$http_status};
    return check_status_code($stash, $http_status_re);
};

# Then the page does not contain "We are sorry"
Then qr{the page should not contain "(.+)"}, sub {
    my $unwanted_string = $1;
    my $found = page_content_contains($stash, $unwanted_string);
    ok(!$found, "  String '$unwanted_string' was not found in the page")
        or diag("Page content: ".$stash->{res}->content);
};

# Then the page contains "We are sorry"
Then qr{the page should contain "(.+)"}, sub {
    my $wanted_string = $1;
    my $found = page_content_contains($stash, $wanted_string);
    ok($found, "  String '$wanted_string' was found in the page")
        or diag("Page content: ".$stash->{res}->content);
};

Then qr{the page (?:is|should be) a valid JSON document}, sub {
    my $content = $stash->{res}->content;
    my $is_json = 0;
    eval {
        my $json = JSON->new();
        my $data = $json->decode($content);
        $is_json = (ref $data eq "ARRAY") || (ref $data eq "HASH");
    };
    ok($is_json, "  Page content is a valid JSON document")
        or diag("Page is not a valid JSON document.\n"
        . "Exception: $@\n"
        . "Content: " . $stash->{res}->content);
};

# Then the page MD5 checksum should be "f5a3cf5f5891652a2b148d40fb400a84"
Then qr{the page MD5 checksum should be "(.+)"}, sub {
    my $correct_md5 = $1;
    eval { require Digest::MD5; 1 }
        or fail("Digest::MD5 required to verify MD5 checksums");
    my $page_content = $stash->{res}->content;
    my $actual_md5 = Digest::MD5::md5_hex($page_content);
    is($actual_md5, $correct_md5, "  MD5 checksum of page content is correct");
};

Then qr{the json document should have a "(.+)" key}, sub {
    my $required_key = $1;
    my $content = $stash->{res}->content;
    my $json_has_key = 0;
    eval {
        my $json = JSON->new();
        my $data = $json->decode($content);
        $json_has_key = Test::Cukes::JSON::document_has_key($data, $required_key);
    };
    ok($json_has_key, "  JSON document has a ${required_key} key")
        or fail("JSON document has no ${required_key} key.\n"
            . "Exception: $@\n"
            . "Content: " . $content);
};

Then qr{the json value for the "(.+)" key should not be empty}, sub {
    my $key = $1;
    my $content = $stash->{res}->content;
    my $key_value;
    eval {
        my $json = JSON->new();
        my $data = $json->decode($content);
        $key_value = Test::Cukes::JSON::key_value($data, $key);
    };
    my $display_val = $key_value || "";
    isnt($key_value => undef, "  JSON key ${key} has non-empty value (`$display_val')")
        or fail("JSON key ${key} has an undefined value.\n"
            . "Exception: $@\n"
            . "Content: " . $content);
};

Then qr{the json value for the "(.+)" key should be "(.+)"}, sub {
    my $key = $1;
    my $expected_value = $2;
    my $content = $stash->{res}->content;
    my $key_value;
    eval {
        my $json = JSON->new();
        my $data = $json->decode($content);
        $key_value = Test::Cukes::JSON::key_value($data, $key);
    };
    is($key_value => $expected_value,
        "  JSON key ${key} should have value `$expected_value' (has `$key_value')")
        or fail("JSON key ${key} has a value that is *not* `$expected_value' "
            . "(has `$key_value').\n"
            . "Exception: $@\n"
            . "Content: " . $content);
};

Then qr{the json value for the "(.+)" key should match "(.+)"}, sub {
    my $key = $1;
    my $value_re = quotemeta($2);
    $value_re = qr{$value_re};
    my $content = $stash->{res}->content;
    my $key_value;
    eval {
        my $json = JSON->new();
        my $data = $json->decode($content);
        $key_value = Test::Cukes::JSON::key_value($data, $key);
    };
    ok($key_value =~ $value_re,
        "  JSON key ${key} matches $value_re (value is `$key_value')")
        or fail("JSON key ${key} doesn't match $value_re (`$key_value')"
            . "Exception: $@\n"
            . "Content: " . $content);
};

Then qr{the json value for the "(.+)" key should be a timestamp within (\d+) (hours?|minutes?|seconds?|days?)}, sub {
    my $key = $1;
    my $units = $2 + 0;
    my $max_diff_secs = $units;
    my $unit = $3;

    if ($unit =~ m{^minute}) {
        $max_diff_secs *= 60;
    }
    elsif ($unit =~ m{^hour}) {
        $max_diff_secs *= 3600;
    }
    elsif ($unit =~ m{^day}) {
        $max_diff_secs *= 86400;
    }

    my $content = $stash->{res}->content;
    my $ts_value;
    eval {
        my $json = JSON->new();
        my $data = $json->decode($content);
        $ts_value = Test::Cukes::JSON::key_value($data, $key);
    } or do {
        diag("Exception: $@");
    };

    my $ts_secs;

    # Unix epoch timestamp?
    if ($ts_value =~ m{^ \d+ $}x) {
        $ts_secs = $ts_value;
    }

    else {
        # Solr/ISO date, but try to get the ".<microseconds>" suffix
        if ($ts_value =~ m{^ \d\d\d\d-\d\d-\d\d T \d\d:\d\d:\d\d \. \d+ $}x) {
            $ts_value =~ s{\.\d+$}{+00:00};
        }
        my $ts = Time::Piece->strptime($ts_value, "%Y-%m-%dT%T+00:00");
        $ts_secs = $ts->epoch();
    }

    my $t = gmtime;                  # Time::Piece version
    my $now_secs = $t->epoch();
    my $diff_secs = $now_secs - $ts_secs;

    ok($diff_secs < $max_diff_secs,
        "  JSON key ${key} has timestamp within $units $unit (${ts_value}, "
        . "diff: ${diff_secs}s)")

    or fail("JSON key ${key} either has an invalid timestamp or a timestamp out of the defined interval of $units $unit.\n"
        . "Timestamp value: $ts_value\n"
        . "In seconds: $ts_secs\n"
        . "Now: $now_secs\n"
        . "Diff in seconds: $diff_secs\n"
        . "Max diff in seconds: $max_diff_secs\n");
};

1;
