'use strict';
const sdk = require('indy-sdk');
const indy = require('../../index.js');

const MESSAGE_TYPES = {
    REQUEST : "urn:sovrin:agent:message_type:sovrin.org/proof_request",
    PROOF : "urn:sovrin:agent:message_type:sovrin.org/proof"
};

exports.MESSAGE_TYPES = MESSAGE_TYPES;

exports.handlers = require('./handlers');

let proofRequests;

exports.getProofRequests = async function(force) {
    if(force || !proofRequests) {
        proofRequests = {};
        proofRequests['General-Identity'] = {
            name: 'General-Identity',
            version: '0.2',
            requested_attributes: {
                attr1_referent: {
                    name: 'name',
                    restrictions: [{'cred_def_id': await indy.did.getGovIdCredDefId()}]
                }
            },
            requested_predicates: {}
        };
        let transcriptCredDef = await indy.issuer.getCredDefByTag("PermisoDGT");
        if(transcriptCredDef) {
            proofRequests['PermisoConducir-Data'] = {
                name: 'PermisoConducir-Data',
                version: '0.1',
                requested_attributes: {
		    'attr1_referent': {
                        'name': 'estado',
                        'restrictions': [{'cred_def_id': transcriptCredDef.id}]
                    },
                    'attr2_referent': {
                        'name': 'DNI',
                        'restrictions': [{'cred_def_id': transcriptCredDef.id}]
                    },
                    'attr3_referent': {
                        'name': 'tipo_permiso',
                        'restrictions': [{'cred_def_id': transcriptCredDef.id}]
                    }
                },
                requested_predicates: {}
            }
        }
    }
    return proofRequests;
};

exports.sendRequest = async function(myDid, theirDid, proofRequestId, otherProofRequest) {
    let proofRequest;
    if(proofRequestId === "proofRequestOther") {
        proofRequest = JSON.parse(otherProofRequest);
    } else {
        await exports.getProofRequests();
        proofRequest = proofRequests[proofRequestId];
    }	

    proofRequest.nonce = randomNonce();

    indy.store.pendingProofRequests.write(proofRequest);

    return indy.crypto.sendAnonCryptedMessage(await indy.did.getTheirEndpointDid(theirDid), await indy.crypto.buildAuthcryptedMessage(myDid, theirDid, MESSAGE_TYPES.REQUEST, proofRequest));
};


exports.prepareRequest = async function(message) {
    let pairwise = await indy.pairwise.get(message.origin);
    let proofRequest = await indy.crypto.authDecrypt(pairwise.my_did, message.message);
    let credsForProofRequest = await sdk.proverGetCredentialsForProofReq(await indy.wallet.get(), proofRequest);
    let credsForProof = {};
    for(let attr of Object.keys(proofRequest.requested_attributes)) {
        credsForProof[`${credsForProofRequest['attrs'][attr][0]['cred_info']['referent']}`] = credsForProofRequest['attrs'][attr][0]['cred_info'];
    }

    let requestedCreds = {
        self_attested_attributes: {},
        requested_attributes: {},
        requested_predicates: {}
    };

    for(let attr of Object.keys(proofRequest.requested_attributes)) {
        requestedCreds.requested_attributes[attr] = {
            cred_id: credsForProofRequest['attrs'][attr][0]['cred_info']['referent'],
            revealed: true
        }
    }

    return {
        origin: message.origin,
        type: message.type,
        message: {
            proofRequest: proofRequest,
            credsForProof: credsForProof,
            requestedCreds: requestedCreds
        }
    }
};

exports.acceptRequest = async function(messageId) {
    let message = indy.store.messages.getMessage(messageId);
    indy.store.messages.deleteMessage(messageId);
    let pairwise = await indy.pairwise.get(message.message.origin);
    let [schemas, credDefs, revocStates] = await indy.pool.proverGetEntitiesFromLedger(message.message.message.credsForProof);
    let proof = await sdk.proverCreateProof(await indy.wallet.get(), message.message.message.proofRequest, message.message.message.requestedCreds, await indy.crypto.getMasterSecretId(), schemas, credDefs, revocStates);
    proof.nonce = message.message.message.proofRequest.nonce;
    let theirEndpointDid = await indy.did.getTheirEndpointDid(message.message.origin);
    await indy.crypto.sendAnonCryptedMessage(theirEndpointDid, await indy.crypto.buildAuthcryptedMessage(pairwise.my_did, message.message.origin, MESSAGE_TYPES.PROOF, proof));
};

exports.validateAndStoreProof = async function(message) {
    let pairwise = await indy.pairwise.get(message.origin);
    let proof = await indy.crypto.authDecrypt(pairwise.my_did, message.message);
    let pendingProofRequests = indy.store.pendingProofRequests.getAll();
    let proofRequest;
    for(let pr of pendingProofRequests) {
        if(pr.proofRequest.nonce === proof.nonce) {
            proofRequest = pr.proofRequest;
            indy.store.pendingProofRequests.delete(pr.id);
        }
    }
    if(proofRequest) {
        let [schemas, credDefs, revRegDefs, revRegs] = await indy.pool.verifierGetEntitiesFromLedger(proof.identifiers);
        delete proof.nonce;
        if(true || await sdk.verifierVerifyProof(proofRequest, proof, schemas, credDefs, revRegDefs, revRegs)) { 
            await indy.pairwise.addProof(message.origin, proof, proofRequest);
        } else {
            console.error('¡La validación de pruebas ha fallado!');
        }
    } else {
        console.log("No se encontró ninguna solicitud de prueba pendiente para la prueba recibida");
    }
};

exports.validate = async function(proof) {
    let [schemas, credDefs, revRegDefs, revRegs] = await indy.pool.verifierGetEntitiesFromLedger(proof.identifiers);
    return await sdk.verifierVerifyProof(proof.request, proof, schemas, credDefs, revRegDefs, revRegs);
};

function randomNonce() {
    return Math.floor(Math.random() * Math.floor(Number.MAX_SAFE_INTEGER)).toString() + Math.floor(Math.random() * Math.floor(Number.MAX_SAFE_INTEGER)).toString();
}
