'use strict';
const sdk = require('indy-sdk');
const indy = require('../../index.js');
const config = require('../../../config');
let wallet;

exports.get = async function() {
    if(!wallet) {
        await exports.setup();
    }
    return wallet;
};

exports.setup = async function () {
    try {
        await sdk.createWallet(
            {id: config.walletName},
            {key: config.userInformation.password}
        );
    } catch (e) {
        if (e.message !== 'WalletAlreadyExistsError') {
            console.warn('La creación de cartera ha fallado con el error: ' + e.message);
            throw e;
        }
    } finally {
        console.info('La cartera ya existe. Intente abrirla');
    }
    wallet = await sdk.openWallet(
        {id: config.walletName},
        {key: config.userInformation.password}
    );
};
