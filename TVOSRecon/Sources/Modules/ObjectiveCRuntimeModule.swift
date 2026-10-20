// ObjectiveCRuntimeModule.swift
// TVOSRecon
//
// Enumerates the entire Objective-C runtime: all registered classes,
// protocols, methods, ivars, and properties. This reveals the full
// API surface available at runtime including private frameworks that
// Apple loads but doesn't expose in public headers. Security researchers
// should look for: private classes that handle security decisions
// (AMFI, sandbox, code signing), XPC connection classes, classes with
// methods that could be swizzled to bypass checks, and the full
// method signatures that reveal undocumented functionality.

import Foundation
import ObjectiveC

final class ObjectiveCRuntimeModule: ReconModule {
    let name = "ObjectiveCRuntime"
    let timeout: TimeInterval = 120

    private let interestingClassNames: [String] = [
        "NSXPCConnection", "NSXPCInterface", "NSXPCListener",
        "LSApplicationWorkspace", "LSApplicationProxy",
        "FBSSystemService", "FBSSceneIdentifier",
        "SBApplication", "SBApplicationController",
        "MCProfileConnection", "MCProfile",
        "BSAuditToken", "BSMachPortTaskNameRight",
        "SecTask", "AMFITrustCache",
        "IOUserClient", "IORegistryEntry",
        "NSTask", "NSConcreteTask",
        "SFAuthorization", "SecCode",
        "TKTokenWatcher", "TKToken",
        "NEVPNManager", "NEConfiguration",
        "GEOMapService", "CLLocationManagerInternal"
    ]

    func run(engine: ReconEngine) {
        enumerateAllClasses(engine: engine)
        enumerateAllProtocols(engine: engine)
        dumpInterestingClasses(engine: engine)
    }

    // MARK: - All Classes

    private func enumerateAllClasses(engine: ReconEngine) {
        var totalCount: UInt32 = 0
        guard let classList = objc_copyClassList(&totalCount) else {
            engine.reportError(module: name, key: "classes", error: "objc_copyClassList returned nil")
            return
        }
        defer { free(UnsafeMutableRawPointer(classList)) }

        engine.report(module: name, key: "classes.totalCount", value: totalCount)

        let detailLimit = 10000
        for i in 0..<Int(totalCount) {
            let cls = classList[i]
            let className = String(cString: class_getName(cls))

            if i < detailLimit {
                let superclass = class_getSuperclass(cls)
                let superName = superclass != nil ? String(cString: class_getName(superclass!)) : "nil"
                engine.report(module: name, key: "class[\(i)].name", value: className)
                engine.report(module: name, key: "class[\(i)].superclass", value: superName)

                var protocolCount: UInt32 = 0
                if let protocols = class_copyProtocolList(cls, &protocolCount) {
                    let protoNames = (0..<Int(protocolCount)).map {
                        String(cString: protocol_getName(protocols[$0]))
                    }
                    free(UnsafeMutableRawPointer(protocols))
                    if !protoNames.isEmpty {
                        engine.report(module: name, key: "class[\(i)].protocols",
                                      value: protoNames.joined(separator: ", "))
                    }
                }
                engine.report(module: name, key: "class[\(i)].instanceSize", value: class_getInstanceSize(cls))
                engine.report(module: name, key: "class[\(i)].version", value: class_getVersion(cls))
            } else {
                let superclass = class_getSuperclass(cls)
                let superName = superclass != nil ? String(cString: class_getName(superclass!)) : "nil"
                engine.report(module: name, key: "class[\(i)].name", value: className)
                engine.report(module: name, key: "class[\(i)].superclass", value: superName)
            }
        }
    }

    // MARK: - All Protocols

    private func enumerateAllProtocols(engine: ReconEngine) {
        var protocolCount: UInt32 = 0
        guard let protocols = objc_copyProtocolList(&protocolCount) else {
            engine.reportError(module: name, key: "protocols", error: "objc_copyProtocolList returned nil")
            return
        }

        engine.report(module: name, key: "protocols.totalCount", value: protocolCount)

        for i in 0..<Int(protocolCount) {
            let proto = protocols[i]
            let protoName = String(cString: protocol_getName(proto))
            engine.report(module: name, key: "protocol[\(i)].name", value: protoName)

            var requiredInstanceCount: UInt32 = 0
            var requiredClassCount: UInt32 = 0
            var optionalInstanceCount: UInt32 = 0
            var optionalClassCount: UInt32 = 0

            let reqInst = protocol_copyMethodDescriptionList(proto, true, true, &requiredInstanceCount)
            free(reqInst)
            let reqClass = protocol_copyMethodDescriptionList(proto, true, false, &requiredClassCount)
            free(reqClass)
            let optInst = protocol_copyMethodDescriptionList(proto, false, true, &optionalInstanceCount)
            free(optInst)
            let optClass = protocol_copyMethodDescriptionList(proto, false, false, &optionalClassCount)
            free(optClass)

            engine.report(module: name, key: "protocol[\(i)].requiredInstanceMethods", value: requiredInstanceCount)
            engine.report(module: name, key: "protocol[\(i)].requiredClassMethods", value: requiredClassCount)
            engine.report(module: name, key: "protocol[\(i)].optionalInstanceMethods", value: optionalInstanceCount)
            engine.report(module: name, key: "protocol[\(i)].optionalClassMethods", value: optionalClassCount)

            var adoptedCount: UInt32 = 0
            if let adopted = protocol_copyProtocolList(proto, &adoptedCount) {
                let adoptedNames = (0..<Int(adoptedCount)).map {
                    String(cString: protocol_getName(adopted[$0]))
                }
                free(UnsafeMutableRawPointer(adopted))
                if !adoptedNames.isEmpty {
                    engine.report(module: name, key: "protocol[\(i)].adopts",
                                  value: adoptedNames.joined(separator: ", "))
                }
            }
        }
    }

    // MARK: - Interesting Classes Deep Dump

    private func dumpInterestingClasses(engine: ReconEngine) {
        for className in interestingClassNames {
            guard let cls = objc_getClass(className) as? AnyClass else {
                engine.report(module: name, key: "interesting.\(className).exists", value: false)
                continue
            }
            engine.report(module: name, key: "interesting.\(className).exists", value: true)

            dumpMethods(engine: engine, cls: cls, className: className, isMetaClass: false)

            if let metaCls = object_getClass(cls) {
                dumpMethods(engine: engine, cls: metaCls, className: className, isMetaClass: true)
            }

            dumpIvars(engine: engine, cls: cls, className: className)
            dumpProperties(engine: engine, cls: cls, className: className)
        }
    }

    private func dumpMethods(engine: ReconEngine, cls: AnyClass, className: String, isMetaClass: Bool) {
        let prefix = isMetaClass ? "interesting.\(className).classMethods" : "interesting.\(className).instanceMethods"
        var methodCount: UInt32 = 0
        guard let methods = class_copyMethodList(cls, &methodCount) else {
            engine.report(module: name, key: "\(prefix).count", value: 0)
            return
        }
        defer { free(methods) }

        engine.report(module: name, key: "\(prefix).count", value: methodCount)

        for i in 0..<Int(methodCount) {
            let method = methods[i]
            let sel = method_getName(method)
            let selName = NSStringFromSelector(sel)
            let imp = method_getImplementation(method)
            let impAddr = unsafeBitCast(imp, to: UInt.self)

            var typeEnc = "unknown"
            if let te = method_getTypeEncoding(method) {
                typeEnc = String(cString: te)
            }

            engine.report(module: name, key: "\(prefix)[\(i)].selector", value: selName)
            engine.report(module: name, key: "\(prefix)[\(i)].typeEncoding", value: typeEnc)
            engine.report(module: name, key: "\(prefix)[\(i)].imp", value: String(format: "0x%lx", impAddr))
            engine.report(module: name, key: "\(prefix)[\(i)].numberOfArguments", value: method_getNumberOfArguments(method))
        }
    }

    private func dumpIvars(engine: ReconEngine, cls: AnyClass, className: String) {
        var ivarCount: UInt32 = 0
        guard let ivars = class_copyIvarList(cls, &ivarCount) else {
            engine.report(module: name, key: "interesting.\(className).ivars.count", value: 0)
            return
        }
        defer { free(ivars) }

        engine.report(module: name, key: "interesting.\(className).ivars.count", value: ivarCount)

        for i in 0..<Int(ivarCount) {
            let ivar = ivars[i]
            let ivarName = ivar_getName(ivar).map { String(cString: $0) } ?? "unnamed"
            let ivarTypeEnc = ivar_getTypeEncoding(ivar).map { String(cString: $0) } ?? "unknown"
            let ivarOffset = ivar_getOffset(ivar)

            engine.report(module: name, key: "interesting.\(className).ivar[\(i)].name", value: ivarName)
            engine.report(module: name, key: "interesting.\(className).ivar[\(i)].typeEncoding", value: ivarTypeEnc)
            engine.report(module: name, key: "interesting.\(className).ivar[\(i)].offset", value: ivarOffset)
        }
    }

    private func dumpProperties(engine: ReconEngine, cls: AnyClass, className: String) {
        var propCount: UInt32 = 0
        guard let props = class_copyPropertyList(cls, &propCount) else {
            engine.report(module: name, key: "interesting.\(className).properties.count", value: 0)
            return
        }
        defer { free(props) }

        engine.report(module: name, key: "interesting.\(className).properties.count", value: propCount)

        for i in 0..<Int(propCount) {
            let prop = props[i]
            let propName = String(cString: property_getName(prop))
            let propAttrs = property_getAttributes(prop).map { String(cString: $0) } ?? "unknown"

            engine.report(module: name, key: "interesting.\(className).property[\(i)].name", value: propName)
            engine.report(module: name, key: "interesting.\(className).property[\(i)].attributes", value: propAttrs)

            var attrCount: UInt32 = 0
            if let attrList = property_copyAttributeList(prop, &attrCount) {
                defer { free(attrList) }
                for j in 0..<Int(attrCount) {
                    let attr = attrList[j]
                    let attrName = String(cString: attr.name)
                    let attrValue = String(cString: attr.value)
                    engine.report(module: name, key: "interesting.\(className).property[\(i)].attr[\(attrName)]", value: attrValue)
                }
            }
        }
    }
}
