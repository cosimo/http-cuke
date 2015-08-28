package Test::Cukes::JSON;

use strict;
use warnings;

use JSON ();
use Test::More;
use URI ();

sub document_has_key {
    my ($json, $key) = @_;
    my $value = key_value($json, $key);
    return defined $value ? 1 : 0;
}

sub key_value {
    my ($json, $key) = @_;

    # $key can be "key1.key2..."
    # Hopefully this rough generalization won't cause much
    # trouble in practice (in case legit keys have '.' in them)
    my @keys;
    my $slash_pos = index($key, '/');
    my $dot_pos = index($key, '.');
    if ($slash_pos > 0 && $dot_pos > 0) {     # Can't be 1st char
        if ($slash_pos < $dot_pos) {
            @keys = split m{/}, $key;
        }
    }
    if (! @keys) {
        @keys = split m{\.}, $key;
    }
    my $found = 1;
    my $doc = $json;

    # Mixed array/hash lookups like .data.popular_articles.0.title should work
    for my $subkey (@keys) {
        last unless defined $doc;

        my $numeric_key = $subkey =~ m{^ \d+ $} ? 1 : 0;
        my $element_type = ref $doc;
        if ($element_type eq 'ARRAY'
            && defined $numeric_key
            && $numeric_key ne ""
            && exists $doc->[0 + $subkey]) {
            $doc = $doc->[0 + $subkey];
        }
        elsif ($element_type eq 'HASH' && exists $doc->{$subkey}) {
            $doc = $doc->{$subkey};
        }
        else {
            $found = 0;
            $doc = undef;
        }
    }

    return ($doc);
}

1;
