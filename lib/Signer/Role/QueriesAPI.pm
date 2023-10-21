package Signer::Role::QueriesAPI;

use v5.38;

use Moo::Role;
use Mojo::UserAgent;

requires qw(
	signer_config
);

sub do_post ($self, $address, %params)
{
	my $ua = Mojo::UserAgent->new;
	my $cfg = $self->signer_config;

	my $http_tx = $ua->post(
		"$cfg->{signer_host}:$cfg->{signer_port}$address",
		json => \%params,
	);

	my $res = $http_tx->result;
	die 'Got HTTP error: ' . $res->message if $res->is_error;
	my $data = $res->json;

	if (!$data->{status}) {
		die 'Got error: ' . $data->{error};
	}

	return $data->{result};
}

