package Signer::Role::Checksums;

use v5.38;

use Moo::Role;
use Mojo::JSON qw(encode_json decode_json);
use Bitcoin::Crypto::Util qw(to_format hash256);

sub _get_checksum ($self, $pwd, $body)
{
	return to_format [hex => hash256(hash256($pwd) . hash256($body))];
}

sub encode_body ($self, $pwd, $data)
{
	my $body = encode_json $data;
	return join ':', $self->_get_checksum($pwd, $body), $body;
}

sub decode_body ($self, $pwd, $body)
{
	my ($checksum, $data) = split /:/, $body, 2;
	if ($self->_get_checksum($pwd, $data) ne $checksum) {
		sleep 2;
		die 'invalid checksum';
	}

	return decode_json $data;
}

