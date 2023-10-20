package Signer::Command::get_pubs;

use v5.38;

use Moo;
use Mooish::AttributeBuilder;
use Mojo::UserAgent;

extends 'Mojolicious::Command';

has field 'description' => (
	default => sub {
		'Get extended public keys from signer',
	},
);

has field 'usage' => (
	default => sub ($self) {
		$self->extract_usage,
	},
);

with qw(
	Signer::Role::HasConfig
	Signer::Role::ReadsPasswords
);

sub run ($self, @args)
{
	my $ua = Mojo::UserAgent->new;
	my $cfg = $self->signer_config;
	my $passwd = $self->read_password;

	my $http_tx = $ua->post(
		"$cfg->{signer_host}:$cfg->{signer_port}/pubs",
		json => { password => $passwd }
	);

	my $res = $http_tx->result;
	die 'Got HTTP error: ' . $res->message if $res->is_error;
	my $data = $res->json;

	if (!$data->{status}) {
		die 'Got error: ' . $data->{error};
	}
	else {
		say $_ for $data->{result}->@*;
	}
}

__END__

=head1 SYNOPSIS

	Usage: APPLICATION get-pubs

	Needs signer_host and signer_port configured in signer.yml.

