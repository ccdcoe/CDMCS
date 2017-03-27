/******************************************************************************/
/*

! under construction

check tuple against suricata alerts stored in elasticsearch by evebox

see https://github.com/ccdcoe/CDMCS/blob/master/Suricata/evebox/esimport.md


 */
'use strict';

var wiseSource     = require('./wiseSource.js')
  , util           = require('util')
  ;

var source;

//////////////////////////////////////////////////////////////////////////////////
function SuricataSource (api, section) {
  var self = this;
  SuricataSource.super_.call(this, api, section);
  this.esHost = this.api.getConfig("suricata", "esHost");
  if (this.esHost === undefined) {
    console.log(this.section, "- No elasticsearch host defined");
    return;
  }
  this.esIndex = this.api.getConfig("suricata", "esIndex");
  if (this.esIndex === undefined) {
    console.log(this.section, "- No elasticsearch index defined");
    return;
  }

  // TODO move it to https://github.com/aol/moloch/blob/master/capture/plugins/wiseService/wiseSource.js#L39
  this.excludeTuples = [];

  this.api.addSource("suricata", this);
}

util.inherits(SuricataSource, wiseSource);

//////////////////////////////////////////////////////////////////////////////////
SuricataSource.prototype.getTuple = function(tuple, cb) {

  console.dir(tuple);

};

//////////////////////////////////////////////////////////////////////////////////
exports.initSource = function(api) {
  var source = new SuricataSource(api, "suricata");
};
//////////////////////////////////////////////////////////////////////////////////
