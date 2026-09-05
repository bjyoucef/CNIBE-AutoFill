param(
    [Parameter(Mandatory=$true)][string]$numCarte,
    [Parameter(Mandatory=$true)][string]$dateNaiss,
    [Parameter(Mandatory=$true)][string]$dateExpir,
    [string]$outputFile = ""
)

Add-Type -AssemblyName System.Windows.Forms

$form = New-Object System.Windows.Forms.Form
$form.Width = 200
$form.Height = 100
$form.WindowState = [System.Windows.Forms.FormWindowState]::Minimized
$form.ShowInTaskbar = $false

$browser = New-Object System.Windows.Forms.WebBrowser
$browser.Dock = [System.Windows.Forms.DockStyle]::Fill
$form.Controls.Add($browser)

$html = @"
<!DOCTYPE html>
<html>
<head><meta http-equiv="X-UA-Compatible" content="IE=edge" /></head>
<body>
    <object id="dzaeidcard" classid="clsid:078EF12E-A5ED-5374-9D3A-DBC93D57750E"></object>
    <div id="result">WAITING</div>
    <script>
        window.onload = function() {
            setTimeout(function() {
                try {
                    var plugin = document.getElementById("dzaeidcard");
                    if (!plugin || !plugin.readers || plugin.readers.length == 0) {
                        document.getElementById("result").innerText = "ERROR:NO_READER";
                        return;
                    }
                    var targetReader = null;
                    // Détecter en priorité le lecteur Contactless / CL, ou celui avec la carte connectée
                    for (var rIdx = 0; rIdx < plugin.readers.length; rIdx++) {
                        var cand = plugin.readers[rIdx];
                        try {
                            cand.connect(2);
                            targetReader = cand;
                            break;
                        } catch(ec) {
                            try { cand.disconnect(); } catch(ed) {}
                        }
                    }
                    if (!targetReader) {
                        document.getElementById("result").innerText = "ERROR:CONNECT_FAILED";
                        return;
                    }

                    var dNaiss = "$dateNaiss";
                    if (dNaiss.substr(0, 2) == '00' || dNaiss.substr(0, 2) == 'xx') dNaiss = '<<' + dNaiss.substr(2, 8);
                    if (dNaiss.substr(3, 2) == '00' || dNaiss.substr(3, 2) == 'xx') dNaiss = dNaiss.substr(0, 3) + '<<' + dNaiss.substr(5, 5);

                    var resp = "";
                    for (var tIdx = 0; tIdx < 2; tIdx++) {
                        resp = targetReader.transcieves("$numCarte", dNaiss, "$dateExpir");
                        if (resp && resp.length > 100) break;
                        try { targetReader.disconnect(); } catch(e3) {}
                        try { targetReader.connect(2); } catch(e4) {}
                    }
                    try { targetReader.disconnect(); } catch(e2) {}

                    document.getElementById("result").innerText = "RESP:" + resp;
                } catch(e) {
                    document.getElementById("result").innerText = "ERROR:" + e.message;
                }
            }, 300);
        };
    </script>
</body>
</html>
"@

$browser.DocumentText = $html

$checkCount = 0
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 500
$timer.Add_Tick({
    $script:checkCount++
    $elem = $browser.Document.GetElementById("result")
    if ($elem) {
        $text = $elem.InnerText
        if ($text -notmatch "^WAITING" -or $script:checkCount -gt 30) {
            $timer.Stop()
            if ($outputFile -ne "") {
                [System.IO.File]::WriteAllText($outputFile, $text)
            } else {
                [Console]::WriteLine($text)
            }
            $form.Close()
        }
    }
})
$timer.Start()

[System.Windows.Forms.Application]::Run($form)
