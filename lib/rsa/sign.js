//
// rsa-sign.js - adding signing functions to RSAKey class.
//
//
// version: 1.0 (2010-Jun-03)
//
// Copyright (c) 2010 Kenji Urushima (kenji.urushima@gmail.com)
//
// This software is licensed under the terms of the MIT License.
// http://www.opensource.org/licenses/mit-license.php
//
// The above copyright and license notice shall be 
// included in all copies or substantial portions of the Software.

//
// Depends on:
//   function sha1.hex(s) of sha1.js
//   jsbn.js
//   jsbn2.js
//   rsa.js
//   rsa2.js
//

// keysize / pmstrlen
//  512 /  128
// 1024 /  256
// 2048 /  512
// 4096 / 1024

// As for _RSASGIN_DIHEAD values for each hash algorithm, see PKCS#1 v2.1 spec (p38).
var _RSASIGN_DIHEAD = [];
_RSASIGN_DIHEAD['sha1'] = "3021300906052b0e03021a05000414";
_RSASIGN_DIHEAD['sha256'] = "3031300d060960864801650304020105000420";
//_RSASIGN_DIHEAD['md2'] = "3020300c06082a864886f70d020205000410";
//_RSASIGN_DIHEAD['md5'] = "3020300c06082a864886f70d020505000410";
//_RSASIGN_DIHEAD['sha384'] = "3041300d060960864801650304020205000430";
//_RSASIGN_DIHEAD['sha512'] = "3051300d060960864801650304020305000440";
var _RSASIGN_HASHHEXFUNC = [];
_RSASIGN_HASHHEXFUNC['sha1'] = sha1.hex;
_RSASIGN_HASHHEXFUNC['sha256'] = sha256.hex;

// ========================================================================
// Signature Generation
// ========================================================================

function _rsasign_getHexPaddedDigestInfoForString(s, keySize, hashAlg) {
  var pmStrLen = keySize / 4;
  var hashFunc = _RSASIGN_HASHHEXFUNC[hashAlg];
  var sHashHex = hashFunc(s);

  var sHead = "0001";
  var sTail = "00" + _RSASIGN_DIHEAD[hashAlg] + sHashHex;
  var sMid = "";
  var fLen = pmStrLen - sHead.length - sTail.length;
  for (var i = 0; i < fLen; i += 2) {
    sMid += "ff";
  }
  sPaddedMessageHex = sHead + sMid + sTail;
  return sPaddedMessageHex;
}

function _rsasign_signString(s, hashAlg) {
  var hPM = _rsasign_getHexPaddedDigestInfoForString(s, this.n.bitLength(), hashAlg);
  var biPaddedMessage = parseBigInt(hPM, 16);
  var biSign = this.doPrivate(biPaddedMessage);
  var hexSign = biSign.toString(16);
  return hexSign;
}

function _rsasign_signStringWithSHA1(s) {
  var hPM = _rsasign_getHexPaddedDigestInfoForString(s, this.n.bitLength(), 'sha1');  
  var biPaddedMessage = parseBigInt(hPM, 16);
  var biSign = this.doPrivate(biPaddedMessage);
  var hexSign = biSign.toString(16);
  return hexSign;
}

function _rsasign_signStringWithSHA256(s) {
  var hPM = _rsasign_getHexPaddedDigestInfoForString(s, this.n.bitLength(), 'sha256');
  var biPaddedMessage = parseBigInt(hPM, 16);
  var biSign = this.doPrivate(biPaddedMessage);
  var hexSign = biSign.toString(16);
  return hexSign;
}

// ========================================================================
// Signature Verification
// ========================================================================

function _rsasign_getDecryptSignatureBI(biSig, hN, hE) {
  var rsa = new RSAKey();
  rsa.setPublic(hN, hE);
  var biDecryptedSig = rsa.doPublic(biSig);
  return biDecryptedSig;
}

function _rsasign_getHexDigestInfoFromSig(biSig, hN, hE) {
  var biDecryptedSig = _rsasign_getDecryptSignatureBI(biSig, hN, hE);
  var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
  return hDigestInfo;
}

function _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo) {
  for (var algName in _RSASIGN_DIHEAD) {
    var head = _RSASIGN_DIHEAD[algName];
    var len = head.length;
    if (hDigestInfo.substring(0, len) == head) {
      var a = [algName, hDigestInfo.substring(len)];
      return a;
    }
  }
  return [];
}

function _rsasign_verifySignatureWithArgs(sMsg, biSig, hN, hE) {
  var hDigestInfo = _rsasign_getHexDigestInfoFromSig(biSig, hN, hE);
  var digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);
  if (digestInfoAry.length == 0) return false;
  var algName = digestInfoAry[0];
  var diHashValue = digestInfoAry[1];
  var ff = _RSASIGN_HASHHEXFUNC[algName];
  var msgHashValue = ff(sMsg);
  return (diHashValue == msgHashValue);
}

function _rsasign_verifyHexSignatureForMessage(hSig, sMsg) {
  var biSig = parseBigInt(hSig, 16);
  var result = _rsasign_verifySignatureWithArgs(sMsg, biSig,
						this.n.toString(16),
						this.e.toString(16));
  return result;
}

function _rsasign_verifyString(sMsg, hSig) {
  hSig = hSig.replace(/[ \n]+/g, "");
  var biSig = parseBigInt(hSig, 16);
  var biDecryptedSig = this.doPublic(biSig);
  var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
  var digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);
  
  if (digestInfoAry.length == 0) return false;
  var algName = digestInfoAry[0];
  var diHashValue = digestInfoAry[1];
  var ff = _RSASIGN_HASHHEXFUNC[algName];
  var msgHashValue = ff(unicodeToUtf8(sMsg));
  return (diHashValue == msgHashValue);
}

function unicodeToUtf8(str) {
    var i, len, ch;
    var utf8Str = "";
    len = str.length;
    for (i = 0; i < len; i++) {
        ch = str.charCodeAt(i);
        
        if ((ch >= 0x0) && (ch <= 0x7F)) {
            utf8Str += str.charAt(i);
            
        } else if ((ch >= 0x80) && (ch <= 0x7FF)){
            utf8Str += String.fromCharCode(0xc0 | ((ch >> 6) & 0x1F));
            utf8Str += String.fromCharCode(0x80 | (ch & 0x3F));
            
        } else if ((ch >= 0x800) && (ch <= 0xFFFF)){
            utf8Str += String.fromCharCode(0xe0 | ((ch >> 12) & 0xF));
            utf8Str += String.fromCharCode(0x80 | ((ch >> 6) & 0x3F));
            utf8Str += String.fromCharCode(0x80 | (ch & 0x3F));
            
        } else if ((ch >= 0x10000) && (ch <= 0x1FFFFF)){
           utf8Str += String.fromCharCode(0xF0 | ((ch >> 18) & 0x7));
           utf8Str += String.fromCharCode(0x80 | ((ch >> 12) & 0x3F));
           utf8Str += String.fromCharCode(0x80 | ((ch >> 6) & 0x3F));
           utf8Str += String.fromCharCode(0x80 | (ch & 0x3F));
           
        } else if ((ch >= 0x200000) && (ch <= 0x3FFFFFF)){
           utf8Str += String.fromCharCode(0xF8 | ((ch >> 24) & 0x3));
           utf8Str += String.fromCharCode(0x80 | ((ch >> 18) & 0x3F));
           utf8Str += String.fromCharCode(0x80 | ((ch >> 12) & 0x3F));
           utf8Str += String.fromCharCode(0x80 | ((ch >> 6) & 0x3F));
           utf8Str += String.fromCharCode(0x80 | (ch & 0x3F));
           
        } else if ((ch >= 0x4000000) && (ch <= 0x7FFFFFFF)){
           utf8Str += String.fromCharCode(0xFC | ((ch >> 30) & 0x1));
           utf8Str += String.fromCharCode(0x80 | ((ch >> 24) & 0x3F));
           utf8Str += String.fromCharCode(0x80 | ((ch >> 18) & 0x3F));
           utf8Str += String.fromCharCode(0x80 | ((ch >> 12) & 0x3F));
           utf8Str += String.fromCharCode(0x80 | ((ch >> 6 ) & 0x3F));
           utf8Str += String.fromCharCode(0x80 | (ch & 0x3F));
           
        }
            
    }
    return utf8Str;
};

RSAKey.prototype.signString = _rsasign_signString;
RSAKey.prototype.signStringWithSHA1 = _rsasign_signStringWithSHA1;
RSAKey.prototype.signStringWithSHA256 = _rsasign_signStringWithSHA256;

RSAKey.prototype.verifyString = _rsasign_verifyString;
RSAKey.prototype.verifyHexSignatureForMessage = _rsasign_verifyHexSignatureForMessage;

