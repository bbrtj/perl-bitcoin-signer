package Signer::Role::HasConfig;

use v5.38;

use Moo::Role;
use Mooish::AttributeBuilder;

my $config;

sub signer_config ($self)
{
	if (!defined $config) {
		$config = $self->app->plugin('NotYAMLConfig');
	}

	return $config;
}

