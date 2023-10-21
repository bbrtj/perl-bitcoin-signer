package Signer::Command::get_pubs;

use v5.38;

use Moo;
use Mooish::AttributeBuilder;

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
	Signer::Role::QueriesAPI
);

sub run ($self, @args)
{
	my $result = $self->do_post('/pubs',
		signer_password => scalar $self->read_password('system'),
		password => scalar $self->read_password('wallet'),
	);

	say $_ for $result->@*;
}

__END__

=head1 SYNOPSIS

	Usage: APPLICATION get-pubs

	Needs signer_host and signer_port configured in signer.yml.

