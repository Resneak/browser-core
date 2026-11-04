"""Closed versions of the private native observation contract."""
CAPTURE_V1 = {'schema':'browser-core.inspection/1','allowlist':'fingerprint-v1'}
CAPTURE_V2 = {'schema':'browser-core.inspection/2','allowlist':'fingerprint-v2'}
CAPTURE_V3 = {'schema':'browser-core.inspection/3','allowlist':'research-v3'}
CAPTURE_OFF = {'schema':'browser-core.metadata/1','allowlist':'none'}
CRYPTO_INPUT_API = 'SubtleCrypto.digest.input'
CRYPTO_INPUT_PATCH = '0041-browser-core-private-hashing-inputs.patch'
NAVIGATOR_GETTERS = (
    'hardwareConcurrency','deviceMemory','userAgent','platform','language','languages',
    'vendor','product','productSub','vendorSub','appVersion','appName','appCodeName',
    'cookieEnabled','onLine','maxTouchPoints','webdriver','pdfViewerEnabled','userAgentData',
)
SCREEN_GETTERS = ('width','height','availWidth','availHeight','availLeft','availTop','colorDepth','pixelDepth')
V1_PARAMETERS = {'WebGLRenderingContext.getParameter':1,'WebGL2RenderingContext.getParameter':1}
APIS_V1 = frozenset(f'{i}.{n}.get' for i in ('Navigator','WorkerNavigator') for n in NAVIGATOR_GETTERS) | frozenset(f'Screen.{n}.get' for n in SCREEN_GETTERS) | V1_PARAMETERS.keys()
V2_GETTERS = {
    'ImageData':('data','width','height','colorSpace','pixelFormat'),
    'TextMetrics':('width','actualBoundingBoxLeft','actualBoundingBoxRight','fontBoundingBoxAscent','fontBoundingBoxDescent','actualBoundingBoxAscent','actualBoundingBoxDescent','emHeightAscent','emHeightDescent','hangingBaseline','alphabeticBaseline','ideographicBaseline'),
    'WebGLShaderPrecisionFormat':('rangeMin','rangeMax','precision'),
    'BaseAudioContext':('sampleRate','currentTime','state'),
    'AudioBuffer':('sampleRate','length','duration','numberOfChannels'),
    'MediaQueryList':('matches','media'),
    'ScreenOrientation':('type','angle'),
    'GPUAdapter':('info','limits'),
    'GPUAdapterInfo':('vendor','architecture','device','description'),
    'NetworkInformation':('effectiveType','rtt','downlink','saveData'),
    'BatteryManager':('level','charging'),
    'FontFaceSet':('status',),
}
V2_PARAMETERS = {
    'HTMLCanvasElement.toDataURL':2,
    'CanvasRenderingContext2D.getImageData':4,
    'OffscreenCanvasRenderingContext2D.getImageData':4,
    'CanvasRenderingContext2D.measureText':1,
    'OffscreenCanvasRenderingContext2D.measureText':1,
    'WebGLRenderingContext.getSupportedExtensions':0,
    'WebGL2RenderingContext.getSupportedExtensions':0,
    'WebGLRenderingContext.getShaderPrecisionFormat':2,
    'WebGL2RenderingContext.getShaderPrecisionFormat':2,
    'AudioBuffer.getChannelData':1,
    'MediaDevices.enumerateDevices':0,
    'SpeechSynthesis.getVoices':0,
    'NavigatorUAData.getHighEntropyValues':1,
    'GPU.requestAdapter':0,
    'StorageManager.estimate':0,
    'Permissions.query':1,
    'MediaRecorder.isTypeSupported':1,
    'HTMLMediaElement.canPlayType':1,
    'FontFaceSet.check':1,
}
APIS_V2 = APIS_V1 | frozenset(f'{i}.{n}.get' for i,names in V2_GETTERS.items() for n in names) | V2_PARAMETERS.keys()
APIS_V3 = APIS_V2 | {CRYPTO_INPUT_API}

def supported_capture(value):
    return isinstance(value,dict) and value in (CAPTURE_V1,CAPTURE_V2,CAPTURE_V3)

def supported_recording_capture(value):
    return value == CAPTURE_OFF or supported_capture(value)

def recording_capture(session):
    """Session v1 omission means private recording was disabled, never unknown v1."""
    from .contracts import ContractError
    value = session.get('value_capture', CAPTURE_OFF)
    if not supported_recording_capture(value):
        raise ContractError('unsupported recording capture contract')
    return dict(value)

def capture_for_allowlist(value):
    return next((dict(c) for c in (CAPTURE_V1,CAPTURE_V2,CAPTURE_V3) if c['allowlist']==value),None)

def capture_apis(capture):
    for version,apis in ((CAPTURE_V1,APIS_V1),(CAPTURE_V2,APIS_V2),(CAPTURE_V3,APIS_V3)):
        if capture==version:return apis
    return frozenset()

def supported_completion(capture,api,completion):
    if api not in capture_apis(capture):return False
    return completion=='input-copied' if api==CRYPTO_INPUT_API else completion in ('returned','exception')

def require_inspection_support(root,allowlist):
    """Reject newer recording requests before any profile or process is created.

    This supplements executable attestation; it never replaces that check. An
    old executable cannot be used with a newer root's attestation requirements.
    """
    from .contracts import ContractError
    from .upstream import verified_patch_names
    if capture_for_allowlist(allowlist) is None:
        raise ContractError('unsupported native inspection version')
    if allowlist==CAPTURE_V3['allowlist'] and CRYPTO_INPUT_PATCH not in verified_patch_names(root):
        raise ContractError('hash input inspection requires a verified native build with the hashing-input patch')

def parameter_count(api,extended):
    return (V2_PARAMETERS.get(api,V1_PARAMETERS.get(api,0)) if extended else V1_PARAMETERS.get(api,0))
