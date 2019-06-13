(function ($) {

    function Settings(s) {
        var settings = {
            publicKey: "publicKey",
            privateKey: "privateKey",
            password: "password",
            loginFail: "El usuario no es valido. Revise sus datos de e.Firma y vuelva a intentarlo."
        };

        if (typeof s === "undefined")
            alert("The host is not set");
        else {
            if (typeof s.host === "undefined" || s.host === "") 
                alert("The host is not set");

            if (typeof s.publicKey === "undefined")
                s["publicKey"] = settings.publicKey;

            if (typeof s.privateKey === "undefined")
                s["privateKey"] = settings.privateKey;

            if (typeof s.password === "undefined")
                s["password"] = settings.password;

            if (typeof s.loginFail === "undefined")
                s["loginFail"] = settings.loginFail;
        }

        return s;
    }

    $.fn.uSignature = function (settings) {
        var signature = this;
        var token = "";
        var signSuccess = {};
        settings = Settings(settings);

        signature = $.extend(this,
            {
                Sign: function (elementInstanceRefId, templates) {
                    var isRequired = true;

                    if (typeof elementInstanceRefId === "undefined" || elementInstanceRefId === "")
                        isRequired = false;

                    if (typeof $("#" + settings.publicKey)[0].files[0] === "undefined" && isRequired === true)
                        isRequired = false;

                    if (typeof $("#" + settings.privateKey)[0].files[0] === "undefined" && isRequired === true)
                        isRequired = false;

                    if ($("#" + settings.password).val() === "" && isRequired === true)
                        isRequired = false;

                    if (isRequired) {

                        if (token !== "") {
                            SignStart(elementInstanceRefId, templates);
                        } else {
                            $.ajax({
                                cache: false,
                                url: "/Account/GetToken",
                                dataType: "json",
                                timeout: 1280000
                            })
                                .done(function (result) {
                                    token = result.token;
                                    SignStart(elementInstanceRefId, templates);
                                })
                                .fail(function (jqXHR, textStatus, errorThrown) {
                                    signature.trigger("error", settings.loginFail);
                                });
                            }
                        

                    }
                    else
                        signature.trigger("error", "No existe la información suficiente para continuar con la firma electrónica.");
                }

            });

        function SignStart(elementInstanceRefId, templates) {
            var formData = new FormData();
            var publicKey = $("#" + settings.publicKey)[0].files[0];
            var privateKey = $("#" + settings.privateKey)[0].files[0];
            var password = $("#" + settings.password).val();

            formData.append("elementInstanceRefId", elementInstanceRefId);
            formData.append("templates", templates);
            formData.append("publicKey", publicKey);

            signature.trigger("starting");

            $.ajax({
                url: settings.host + "/Sign/Start",
                data: formData,
                processData: false,
                contentType: false,
                enctype: "multipart/form-data",
                type: "POST",
                headers: { Authorization: token },
                timeout: 1280000
            })
                .done(function (signResults) {
                    if (signResults.length > 0) {
                        for (var i = 0; i < signResults.length; i++) {
                            signSuccess[signResults[i].key] = false;
                        }

                        for (var j = 0; j < signResults.length; j++) {
                            switch (signResults[j].type) {

                                case 1:
                                    SignTextEnd(publicKey, privateKey, password, elementInstanceRefId, signResults[j].content, signResults[j].key, signResults[j].template);
                                    break;
                                case 2:
                                    SignPDFEnd(publicKey, privateKey, password, elementInstanceRefId, signResults[j].content, signResults[j].key, signResults[j].template);
                                    break;
                            }
                        }
                    }
                    else
                        signature.trigger("error", "No existe la información suficiente para continuar con la firma electrónica.");
                })
                .fail(function (jqXHR, textStatus, errorThrown) {
                    signature.trigger("error", settings.loginFail);
                });
        }

        function SignTextEnd(publicKey, privateKey, password, elementInstanceRefId, content, key, template) {            
            Signature.Crypto.SignAsync(privateKey, password, content, "sha256")
                .done(function (result) {
                    if (result.error) {
                        signature.trigger("error", result.error);
                        return false;
                    }
                    
                    var formData = new FormData();
                    formData.append("elementInstanceRefId", elementInstanceRefId);
                    formData.append("key", key);
                    formData.append("template", template);
                    formData.append("publicKey", publicKey);
                    formData.append("digitalSignature", Signature.Crypto.ArrayToBase64(result.signatureAsArray));

                    $.ajax({
                        url: settings.host + "/Sign/Text/End",
                        data: formData,
                        processData: false,
                        contentType: false,
                        enctype: 'multipart/form-data',
                        type: 'POST',
                        headers: { Authorization: token },
                        timeout: 1280000
                    })
                        .done(function (result) {
                            if (result === true) {
                                SignSuccess(key);
                            } else {
                                signature.trigger("error", settings.loginFail);
                                console.log("Fail to create: " + template);
                            }                            
                        })
                        .fail(function (jqXHR, textStatus, errorThrown) {
                            signature.trigger("error", errorThrown);
                        });
                })
                .fail(function (result) {
                    signature.trigger("error", settings.loginFail);
                });
        }

        function SignPDFEnd(publicKey, privateKey, password, elementInstanceRefId, content, key, template) {
            Signature.Crypto.SignAsync(privateKey, password, content, "sha256")
                .done(function (result) {
                    if (result.error) {
                        signature.trigger("error", result.error);
                        return false;
                    }

                    var formData = new FormData();
                    formData.append("elementInstanceRefId", elementInstanceRefId);
                    formData.append("key", key);
                    formData.append("template", template);
                    formData.append("publicKey", publicKey);
                    formData.append("privateKey", privateKey);
                    formData.append("pk", password);
                    formData.append("digitalSignature", Signature.Crypto.ArrayToBase64(result.signatureAsArray));

                    $.ajax({
                        url: settings.host + "/Sign/PDF/End",
                        data: formData,
                        processData: false,
                        contentType: false,
                        enctype: 'multipart/form-data',
                        type: 'POST',
                        headers: { Authorization: token },
                        timeout: 1280000
                    })
                        .done(function (result) {
                            if (result === true) {
                                SignSuccess(key);
                            } else {
                                signature.trigger("error", settings.loginFail);
                                console.log("Fail to create: " + template);
                            }
                        })
                        .fail(function (jqXHR, textStatus, errorThrown) {
                            signature.trigger("error", errorThrown);
                        });
                })
                .fail(function (result) {
                    signature.trigger("error", settings.loginFail);
                });
        }

        function SignSuccess(currentKey) {
            signSuccess[currentKey] = true;

            var done = true;
            for (var key in signSuccess) {
                if (signSuccess[key] === false)
                    done = false;
            }

            if (done)
                signature.trigger("done");
        }

        return signature;
    };
})(jQuery);