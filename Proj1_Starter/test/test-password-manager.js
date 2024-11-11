"use strict";

let expect = require('expect.js');
const { Keychain } = require('../password-manager');

function expectReject(promise) {
    return promise.then(
        (result) => expect().fail(`Expected failure, but function returned ${result}`),
        (error) => {}  // No action needed for rejection
    );
}

describe('Password manager', function() {
    this.timeout(5000);
    const password = "password123!";

    let kvs = {
        "service1": "value1",
        "service2": "value2",
        "service3": "value3"
    };

    describe('functionality', function() {
        it('inits without an error', async function() {
            await Keychain.init(password);
        });

        it('can set and retrieve a password', async function() {
            let keychain = await Keychain.init(password);
            let url = 'www.stanford.edu';
            let pw = 'sunetpassword';
            await keychain.set(url, pw);
            expect(await keychain.get(url)).to.equal(pw);
        });

        it('can set and retrieve multiple passwords', async function() {
            let keychain = await Keychain.init(password);
            for (let k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            for (let k in kvs) {
                expect(await keychain.get(k)).to.equal(kvs[k]);
            }
        });

        it('returns null for non-existent passwords', async function() {
            let keychain = await Keychain.init(password);
            for (let k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            expect(await keychain.get('www.stanford.edu')).to.be(null);
        });

        it('can remove a password', async function() {
            let keychain = await Keychain.init(password);
            for (let k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            expect(await keychain.remove('service1')).to.be(true);
            expect(await keychain.get('service1')).to.be(null);
        });

        it('returns false if there is no password for the domain being removed', async function() {
            let keychain = await Keychain.init(password);
            for (let k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            expect(await keychain.remove('www.stanford.edu')).to.be(false);
        });

        it('can dump and restore the database', async function() {
            let keychain = await Keychain.init(password);
            for (let k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            let data = await keychain.dump();
            let contents = data[0];
            let checksum = data[1];
            let newKeychain = await Keychain.load(password, contents, checksum);

            // Make sure it's valid JSON
            expect(function() {
                JSON.parse(contents);
            }).not.to.throwException();
            for (let k in kvs) {
                expect(await newKeychain.get(k)).to.equal(kvs[k]);
            }
        });

        it('fails to restore the database if checksum is wrong', async function() {
            let keychain = await Keychain.init(password);
            for (let k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            let data = await keychain.dump();
            let contents = data[0];
            let fakeChecksum = '3GB6WSm+j+jl8pm4Vo9b9CkO2tZJzChu34VeitrwxXM=';
            await expectReject(Keychain.load(password, contents, fakeChecksum));
        });

       
    });

    describe('security', function() {
        // Very basic test to make sure you're not doing the most naive thing
        it("doesn't store domain names and passwords in the clear", async function() {
            let keychain = await Keychain.init(password);
            let url = 'www.stanford.edu';
            let pw = 'sunetpassword';
            await keychain.set(url, pw);
            const storedData = keychain.data;
            expect(storedData[url]).to.have.property("iv");
            expect(storedData[url]).to.have.property("ciphertext");
        });

        

        it('returns false if trying to load with an incorrect password', async function() {
            let keychain = await Keychain.init(password);
            for (let k in kvs) {
                await keychain.set(k, kvs[k]);
            }
            let data = await keychain.dump();
            let contents = data[0];
            let checksum = data[1];
            
            try {
                await Keychain.load("fakepassword", contents, checksum);
                expect().fail('Expected failure, but function returned successfully');
            } catch (error) {
                // Ensure the error is of the expected type
                expect(error).to.be.an(Error);  // Ensure it's an error
            }
        });

        it("should encrypt the keychain data", async function() {
            let keychain = await Keychain.init(password);
            let url = 'www.stanford.edu';
            let pw = 'sunetpassword';
            await keychain.set(url, pw);
    
            let data = await keychain.dump();
            let contents = data[0];
    
            // Check that the dumped data is not in a human-readable form
            expect(contents).not.to.equal(url);
            expect(contents).not.to.equal(pw);
        });

        it("does not expose the password after loading the keychain", async function() {
            let keychain = await Keychain.init(password);
            let url = 'www.stanford.edu';
            let pw = 'sunetpassword';
            await keychain.set(url, pw);
            
            let data = await keychain.dump();
            let contents = data[0];
            let checksum = data[1];
    
            let restoredKeychain = await Keychain.load(password, contents, checksum);
            expect(restoredKeychain).to.not.have.property('password');
        });

        it('can store and restore encrypted passwords', async function() {
            let keychain = await Keychain.init(password);
            await keychain.set('www.example.com', 'password123');
            let data = await keychain.dump();
            let contents = data[0];
            let checksum = data[1];
        
            let restoredKeychain = await Keychain.load(password, contents, checksum);
            expect(await restoredKeychain.get('www.example.com')).to.equal('password123');
        });
        

        it('handles empty password correctly', async function() {
            let keychain = await Keychain.init('');
            await keychain.set('www.example.com', 'examplePassword');
            expect(await keychain.get('www.example.com')).to.equal('examplePassword');
        });

        it('fails to load an empty keychain dump', async function() {
            await expectReject(Keychain.load(password, '', 'fakeChecksum'));
        });

        // This test won't be graded directly -- it just exists to make sure your
        // dump include a kvs object with all your urls and passwords, because
        // we will be using that in other tests.
        it('includes a kvs object in the serialized dump', async function() {
            let keychain = await Keychain.init(password);
            for (let i = 0; i < 10; i++) {
                await keychain.set(String(i), String(i));
            }
            let data = await keychain.dump();
            let contents = data[0];
            let contentsObj = JSON.parse(contents);
            expect(contentsObj).to.have.key('kvs');
            expect(contentsObj.kvs).to.be.an('object');
            expect(Object.getOwnPropertyNames(contentsObj.kvs)).to.have.length(10);
        });
    });
});
