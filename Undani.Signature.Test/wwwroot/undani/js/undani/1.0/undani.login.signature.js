(function ($) {

    function Settings(s) {
        var settings = {
            publicKey: "publicKey",
            privateKey: "privateKey",
            password: "password"
        };

        if (typeof s === "undefined")
            alert("The host is not set");
        else {
            if (typeof s.publicKey === "undefined")
                s["publicKey"] = settings.publicKey;

            if (typeof s.privateKey === "undefined")
                s["privateKey"] = settings.privateKey;

            if (typeof s.password === "undefined")
                s["password"] = settings.password;
        }

        return s;
    }

    $.fn.uLoginSignature = function (settings) {
        var signature = this;
        settings = Settings(settings);

        signature = $.extend(this,
            {
                Sign: function () {
                    var isRequired = true;

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

                        formData.append("token", settings.token);
                        formData.append("environmentId", settings.environmentId);
                        formData.append("formInstanceId", settings.instanceId);
                        formData.append("publicKey", publicKey);

                        signature.trigger("starting");

                        var result = { contentAsBase64: "MTIzNDU=" };

                        SealWithPrivateKey(settings.token, publicKey, privateKey, password, result);

                    }
                    else
                        signature.trigger("error", "Ingrese la información requerida para la firma.");
                }
            });

        function SealWithPrivateKey(token, publicKey, privateKey, password, pkr) {
            Signature.Crypto.SignAsync(privateKey, password, pkr.contentAsBase64, "sha256")
                .done(function (result) {
                    if (result.error) {
                        signature.trigger("error", result.error);
                        return;
                    }
                    
                    signature.trigger("done");
                })
                .fail(function (result) {
                    signature.trigger("error", result.error);
                });
        }

        return signature;
    };
})(jQuery);