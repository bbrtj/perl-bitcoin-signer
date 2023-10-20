package Signer::Role::HasConfig;

use v5.38;

use Moo::Role;
use Mooish::AttributeBuilder;

has field 'signer_config' => (
	lazy => sub ($self) {
		return $self->app->plugin('NotYAMLConfig');
	},
);

