(function ($) {

    function Settings(s) {
        var settings = {
            ownerId: "00000000-0000-0000-0000-000000000000",
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

            if (typeof s.ownerId === "undefined")
                s["ownerId"] = settings.ownerId;

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

    $.fn.uLoginSignature = function (settings) {
        var signature = this;
        var _user = {};
        settings = Settings(settings);

        signature = $.extend(this,
            {
                Login: function (content) {
                    var isRequired = true;

                    if (typeof content === "undefined")
                        content = {};

                    if (typeof $("#" + settings.publicKey)[0].files[0] === "undefined")
                        isRequired = false;

                    if (typeof $("#" + settings.privateKey)[0].files[0] === "undefined" && isRequired === true)
                        isRequired = false;

                    if ($("#" + settings.password).val() === "" && isRequired === true)
                        isRequired = false;

                    if (isRequired) {

                        var formData = new FormData();
                        var publicKey = $("#" + settings.publicKey)[0].files[0];
                        var privateKey = $("#" + settings.privateKey)[0].files[0];
                        var password = $("#" + settings.password).val();

                        formData.append("publicKey", publicKey);

                        signature.trigger("starting");

                        $.ajax({
                            url: settings.host + "/Sign/Login/Start",
                            data: formData,
                            processData: false,
                            contentType: false,
                            enctype: 'multipart/form-data',
                            type: 'POST',
                            timeout: 1280000
                        })
                            .done(function (signNumber) {
                                SealWithPrivateKey(publicKey, privateKey, password, signNumber, content);
                            })
                            .fail(function (jqXHR, textStatus, errorThrown) {
                                signature.trigger("error", errorThrown);
                            });

                    }
                    else
                        signature.trigger("error", "Ingrese los campos mínimos requeridos.");
                },
                ContentExists: function (content) {
                    var formData = new FormData();
                    formData.append("ownerId", settings.ownerId);
                    formData.append("content", JSON.stringify(content));

                    $.ajax({
                        url: settings.host + "/Sign/User/ContentExists",
                        data: formData,
                        processData: false,
                        contentType: false,
                        enctype: 'multipart/form-data',
                        type: 'POST',
                        timeout: 1280000
                    })
                        .done(function (exists) {
                            signature.trigger("contentexists", exists);
                        })
                        .fail(function (jqXHR, textStatus, errorThrown) {
                            signature.trigger("error", errorThrown);
                        });
                },
                User: function () {
                    return _user;
                }
            });

        function SealWithPrivateKey(publicKey, privateKey, password, signNumber, content) {
            Signature.Crypto.SignAsync(privateKey, password, signNumber, "sha256")
                .done(function (result) {
                    if (result.error) {
                        signature.trigger("error", " Lo sentimos, su contraseña no es correcta.");
                        return;
                    }

                    var formData = new FormData();
                    formData.append("ownerId", settings.ownerId);
                    formData.append("publicKey", publicKey);
                    formData.append("digitalSignature", Signature.Crypto.ArrayToBase64(result.signatureAsArray));
                    formData.append("content", JSON.stringify(content));

                    $.ajax({
                        url: settings.host + "/Sign/Login/End",
                        data: formData,
                        processData: false,
                        contentType: false,
                        enctype: 'multipart/form-data',
                        type: 'POST',
                        timeout: 1280000
                    })
                        .done(function (user) {
                            _user = user;
                            signature.trigger("done", user);
                        })
                        .fail(function (jqXHR, textStatus, errorThrown) {
                            signature.trigger("error", "Lo sentimos, la llave no corresponde al certificado que proporcionó.");
                        });
                })
                .fail(function (result) {
                    signature.trigger("error", "Lo sentimos, su contraseña no es correcta.");
                });
        }

        return signature;
    };
})(jQuery);