<?php
/**
 * Metadata for configuration manager plugin
 * Additions for the dokupubsub plugin
 *
 * @author    Robin Gareus <robin@gareus.org>
 */
$meta['enable publishing'] = array('onoff');
$meta['target_host']       = array('string');
$meta['target_port']       = array('numeric');
$meta['target_proto']      = array('multichoice', '_choices' => array('HTTP','HTTPS', 'HTTPS-noCert'));
$meta['target_path']       = array('string');
$meta['target_ns']         = array('string');

//Setup VIM: ex: et ts=2 enc=utf-8 :
