GOAL_DETECTOR_MAP = {
    "LLM01_PROMPT_INJECTION": [
        "garak.detectors.dan.DAN",
        "garak.detectors.dan.DANJailbreak",
        "garak.detectors.dan.DevMode",
        "garak.detectors.dan.AntiDAN",
        "garak.detectors.dan.DUDE",
        "garak.detectors.dan.STAN",
        "garak.detectors.dan.MarkdownLink",
        "garak.detectors.encoding.DecodeMatch",
        "garak.detectors.encoding.DecodeApprox",

        # 알려진 악성 시그니처 포함 여부
        "garak.detectors.knownbadsignatures.EICAR",

        # 유해/독성 콘텐츠 생성 여부 (injection 성공 후 유해 출력)
        "garak.detectors.toxicity.ToxicCommentModel",

        # 모델이 악성 코드를 생성했는지 (injection 성공 시 자주 발생)
        "garak.detectors.malwaregen.AnyCode",
    ],

    "LLM04_DATA_AND_MODEL_POISONING": [
        "garak.detectors.toxicity.ToxicCommentModel",
        "garak.detectors.malwaregen.AnyCode",
        "garak.detectors.knownbadsignatures.EICAR",
        "garak.detectors.knownbadsignatures.GTUBE",
        "garak.detectors.knownbadsignatures.GTphish",
        "garak.detectors.leakreplay.StartsWith",
        "garak.detectors.continuation.Continuation",
    ],

    "LLM09_HALLUCINATION": [
        "garak.detectors.misleading.MustContradictNLI",
        "garak.detectors.misleading.MustRefuteClaimKW",
        "garak.detectors.misleading.MustRefuteClaimModel",
        "garak.detectors.snowball.DontStartYes",
        "garak.detectors.snowball.DontStartNo",
        "garak.detectors.packagehallucination.PythonPypi",
        "garak.detectors.lmrc.QuackMedicine",
    ],
}