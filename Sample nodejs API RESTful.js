/**
 * Created by u999846 on 3/3/2016.
 */
(function () {
    'use strict';

    var url = require('url'),
        request = require('request'),
        access = require('apigee-access'),
        util = require('util'),
        xml2js = require('xml2js'),
        http = require('http'),
        _ = require('lodash');

    var builderBody = new xml2js.Builder({explicitArray: true, explicitRoot: false, rootName: 'v1:FraudNotifyReqPayld'});
    var builderHeader = new xml2js.Builder({explicitArray: true, explicitRoot: false, rootName: 'v3:VantivESBHeader'});

    module.exports.immunity = function(req, res) {
        //  var license = access.getVariable(req, 'vantiv.licence.base64');
        var body = req.body;
        var headers = ['ElapsedTime', 'Environment', 'MessageDateTime','MessageID', 'TransactionID', 'EndUserID',  'Source', 'Target', 'Payload', 'Facts'];
        var pickedHeader = _.pick(body, headers);
        body = _.omit(body, headers);
        var license = req.headers['authorization'];
        license = license.split('\"');
        license = license[1];
        license = new Buffer(license).toString('base64');
        var body = builderBody.buildObject(body);
        var VantivHeader = builderHeader.buildObject(pickedHeader);

        var soapReq = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
            +"<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:v3=\"http://ns.vantiv.com/canonical/schema/ESBHeader/v3\" xmlns:v1=\"https://ws.vantiv.com/Payment/FraudCheck/v1\">"
            + " <soapenv:Header>"
            + "<wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
            +   "<wsse:BinarySecurityToken ValueType=\"wsse:X509v3\" EncodingType=\"wsse:Base64Binary\" Id=\"X509Token\">"
            + license
            +"</wsse:BinarySecurityToken>"
            + "</wsse:Security>"
            +VantivHeader
            + "</soapenv:Header>"
            + "<soapenv:Body>"
            + body
            + "</soapenv:Body>"
            + "</soapenv:Envelope>";


        var header = {
            "ContentType": "text/xml"
        };
        var postRequest = {
            uri: 'https://ws-stage.infoftps.com:4443/merchant/fraudcheck/v1',
            headers: header,
            body: soapReq
        };
        //we have no backend to call outside of the proxy yet
        //res.send("Json payload verified.\nSending Call to Backend");
        res.send(soapReq);
        /*
         console.log("sending request.......");
         request.post(postRequest, function (error, response, body) {
         if (error)
         res.status(error.status_code).send(error);
         else
         res.status(res.status_code).send(response, body);
         });
         */
    };
})();
App.js
(function() {
    var express = require('express'),
        tools = require('swagger-tools'),
        parser = require('body-parser'),
        util = require('util'),
        url = require('url'),
        _ = require('lodash'),
        xmlParser = require('express-xml-bodyparser');

    var app = express(),
        port = process.env.PORT || 9000,



        spec = require('./api/swagger.json')
    tools.initializeMiddleware(spec, function (middleware) {
        //app.use(parser.json());
        /*app.use(xmlParser({
         'normalizeTags': false,
         'explicitArray': false,
         'attrkey': 'attr'
         }));*/
        app.use(middleware.swaggerMetadata());
        app.use(middleware.swaggerValidator());
        app.use(errorHandler);
        app.use(middleware.swaggerRouter({controllers: './controllers'}));
    });
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    app.listen(port);


    function errorHandler (err, req, res, next) {
        if (err && err.results) {
            var serverErrors = err.results.errors
                ,   clientErrors = [];

            _.forEach(serverErrors, function (error) {
                clientErrors.push(resolveError(error));
            });

            res.json({
                'message': 'Your request was malformed',
                'errors': clientErrors
            });
        } else {
            next();
        }
    }

    function resolveError (error) {
        switch (error.code) {
            case 'INVALID_TYPE':
                return {
                    'message': error.message,
                    'field': error.path.join('.')
                };
            case 'OBJECT_MISSING_REQUIRED_PROPERTY':
                var lastSpace = error.message.lastIndexOf(' ');
                var field = error.message.substring(lastSpace + 1);
                var path = error.path.length === 0 ? undefined : error.path.join('.');

                return {
                    'message': error.message,
                    'field': path ? util.format('%s.%s', path, field) : field
                };
            default:
                return error;
        }
    }
})();


