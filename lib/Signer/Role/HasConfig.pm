package Signer::Role::HasConfig;

use v5.40;

use Mooish::Base -role;
use Mojo::DOM;
use Mojo::File qw(path);

my $config;

sub signer_config ($self)
{
	if (!defined $config) {
		my $dom = Mojo::DOM->new(path('signer.xml')->slurp);
		my $root = $dom->at('config');
		my %fields = map {
			$_->attr('name') => $_->text
		} $root->children->to_array->@*;
		$config = \%fields;
	}

	return $config;
}

